using System.Collections.Frozen;
using System.Diagnostics.Metrics;
using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Abstractions.Context;
using AgentShield.Domain.Policy;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AgentShield.Infrastructure.AiCapacity;

/// <summary>
/// In-process <see cref="IAiCapacityGate"/>: rolling per-minute and per-day request budgets and a rolling per-minute
/// input-token budget, each with per-client guaranteed and maximum shares, plus global and per-client concurrency limits
/// (docs/security/ai-analysis.md, section 16). Tokens are only a number here: the estimate comes from the provider
/// adapter through the AI stage, so no tokenisation or provider knowledge lives in the gate.
/// </summary>
/// <remarks>
/// <para>State is per process (one instance, like the API rate limiter; ADR 0015) and resets on restart. Every decision
/// is taken under one lock and never waits: a call that cannot start now is refused.</para>
/// <para>State is keyed by the configured analysis client IDs only (<see cref="IApiClientDirectory"/>), fixed at startup.
/// An unknown client ID is refused and never stored, so no credential or caller-chosen value can enter the state, and
/// memory is bounded by the configuration.</para>
/// <para>Admitted calls count against the request budgets, and their reserved input-token estimate against the token
/// budget, whatever their outcome (a failed or timed-out call may still have reached the provider and counted against its
/// quota). A refused call reserves nothing. Only the concurrency slot is returned when the admission is disposed.</para>
/// <para>Refusals are logged at most once per client per minute (EventId 1200), with the limit that refused them; the
/// client only ever sees the generic review finding. Every decision is counted in the
/// <c>agentshield.ai.admissions</c> metric, tagged with a fixed <c>result</c> value.</para>
/// </remarks>
internal sealed partial class InMemoryAiCapacityGate : IAiCapacityGate
{
    public const string MeterName = "AgentShield.AI";
    public const string AdmissionsInstrument = "agentshield.ai.admissions";
    public const string ResultTag = "result";
    public const string TokenAdmissionsInstrument = "agentshield.ai.token_admissions";
    public const string ReservedInputTokensInstrument = "agentshield.ai.input_tokens.reserved";

    private readonly Lock _lock = new();
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<InMemoryAiCapacityGate> _logger;
    private readonly Counter<long> _admissions;
    private readonly Counter<long> _tokenAdmissions;
    private readonly Counter<long> _reservedInputTokens;
    private readonly RequestBudget _inputTokensPerMinute;
    private readonly bool _skipWhenDeterministicBlock;
    private readonly int _maxConcurrentCalls;
    private readonly int _clientMaxConcurrentCalls;
    private readonly long _minute;
    private readonly RequestBudget _perMinute;
    private readonly RequestBudget _perDay;
    private readonly FrozenDictionary<string, ClientState> _clients;
    private int _inFlight;
    private long? _unknownClientWarnedAt;

    public InMemoryAiCapacityGate(
        IOptions<AiCapacityOptions> options,
        IApiClientDirectory clientDirectory,
        TimeProvider timeProvider,
        IMeterFactory meterFactory,
        ILogger<InMemoryAiCapacityGate> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(clientDirectory);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(meterFactory);
        ArgumentNullException.ThrowIfNull(logger);

        // Startup validation guarantees complete settings whenever AI is enabled. Otherwise (AI disabled) the gate is
        // never asked, and a missing value means "no capacity": refused and held for review, never invented.
        var settings = options.Value;
        var client = settings.DefaultClient ?? new AiClientCapacityOptions();

        _timeProvider = timeProvider;
        _logger = logger;
        _skipWhenDeterministicBlock = settings.SkipWhenDeterministicBlock ?? false;
        _maxConcurrentCalls = settings.MaxConcurrentCalls;
        _clientMaxConcurrentCalls = client.MaxConcurrentCalls;
        _minute = checked(timeProvider.TimestampFrequency * 60);

        var clientIds = clientDirectory.AnalysisClientIds;
        _perMinute = new RequestBudget(_minute, settings.GlobalRequestsPerMinute, client.GuaranteedPerMinute, client.MaxPerMinute, clientIds);
        _perDay = new RequestBudget(checked(_minute * 60 * 24), settings.GlobalRequestsPerDay, client.GuaranteedPerDay, client.MaxPerDay, clientIds);
        _inputTokensPerMinute = new RequestBudget(
            _minute, settings.GlobalInputTokensPerMinute, client.GuaranteedInputTokensPerMinute, client.MaxInputTokensPerMinute, clientIds);
        _clients = clientIds.ToFrozenDictionary(id => id, _ => new ClientState(), StringComparer.Ordinal);

        var meter = meterFactory.Create(MeterName);
        _admissions = meter.CreateCounter<long>(
            AdmissionsInstrument,
            unit: "{admission}",
            description: "AI capacity admission decisions, by result.");
        _tokenAdmissions = meter.CreateCounter<long>(
            TokenAdmissionsInstrument,
            unit: "{admission}",
            description: "AI calls whose input-token reservation was accepted (the call was admitted) or rejected (the token budget refused it).");
        _reservedInputTokens = meter.CreateCounter<long>(
            ReservedInputTokensInstrument,
            unit: "{token}",
            description: "Estimated input tokens reserved by admitted AI calls.");
    }

    /// <summary>The client IDs the gate keeps state for (tests: proves no other value, such as a key, is stored).</summary>
    internal IReadOnlyCollection<string> TrackedClientIds => _clients.Keys;

    /// <summary>AI calls in flight now (tests).</summary>
    internal int InFlight
    {
        get
        {
            lock (_lock)
            {
                return _inFlight;
            }
        }
    }

    public bool IsCallNeeded(SecurityDecision deterministicDecision)
    {
        if (_skipWhenDeterministicBlock && deterministicDecision == SecurityDecision.Block)
        {
            Count(AdmissionResult.NotNeeded);
            return false;
        }

        return true;
    }

    public AiAdmission TryAdmit(AiAdmissionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentOutOfRangeException.ThrowIfNegative(request.EstimatedInputTokens);

        // Same rule as IsCallNeeded, for a caller that did not ask first.
        if (_skipWhenDeterministicBlock && request.DeterministicDecision == SecurityDecision.Block)
        {
            Count(AdmissionResult.NotNeeded);
            return AiAdmission.NotNeeded;
        }

        var clientId = request.ClientId ?? string.Empty;
        ClientState? client;
        Decision decision;
        lock (_lock)
        {
            var now = _timeProvider.GetTimestamp();
            if (!_clients.TryGetValue(clientId, out client))
            {
                var warn = _unknownClientWarnedAt is not { } warnedAt || now - warnedAt >= _minute;
                _unknownClientWarnedAt = warn ? now : _unknownClientWarnedAt;
                decision = new Decision(AdmissionResult.CapacityExceeded, CapacityLimit.UnknownClient, warn);
            }
            else
            {
                decision = Decide(clientId, client, now, request.EstimatedInputTokens);
            }
        }

        // The admission owns the concurrency slot from here on. Metrics and logs come after it, and if one of them throws
        // (a failing metrics listener), the slot goes back before the exception leaves: observability never changes the
        // accounting. The request and token budgets stay charged, as for any admitted call.
        var admission = decision.Result switch
        {
            AdmissionResult.Guaranteed or AdmissionResult.Shared => AiAdmission.Admitted(() => Release(client!)),
            AdmissionResult.ConcurrencyExceeded => AiAdmission.ConcurrencyExceeded,
            _ => AiAdmission.CapacityExceeded,
        };

        try
        {
            Report(request, decision, client, clientId);
        }
        catch
        {
            admission.Dispose();
            throw;
        }

        return admission;
    }

    /// <summary>The metrics and the throttled warning for one admission decision (outside the lock).</summary>
    private void Report(AiAdmissionRequest request, Decision decision, ClientState? client, string clientId)
    {
        Count(decision.Result);
        if (decision.Result is AdmissionResult.Guaranteed or AdmissionResult.Shared)
        {
            _tokenAdmissions.Add(1, new KeyValuePair<string, object?>(ResultTag, "accepted"));
            _reservedInputTokens.Add(request.EstimatedInputTokens);
        }
        else if (decision.Limit is CapacityLimit.GlobalInputTokensPerMinute or CapacityLimit.ClientInputTokensPerMinute)
        {
            _tokenAdmissions.Add(1, new KeyValuePair<string, object?>(ResultTag, "rejected"));
        }

        if (decision.Warn)
        {
            // Never the unknown value itself: it is not a configured client ID and could be anything.
            if (client is null)
            {
                LogUnknownClientRefused(_logger);
            }
            else
            {
                LogRefused(_logger, clientId, decision.Limit);
            }
        }
    }

    /// <summary>Checks every limit and, if all pass, takes the admission. Runs under <see cref="_lock"/>.</summary>
    private Decision Decide(string clientId, ClientState client, long now, long inputTokens)
    {
        var minute = _perMinute.Check(clientId, now);
        var day = _perDay.Check(clientId, now);
        var tokens = _inputTokensPerMinute.Check(clientId, now, inputTokens);
        var limit = (minute, day, tokens) switch
        {
            (BudgetShare.ClientLimitReached, _, _) => CapacityLimit.ClientRequestsPerMinute,
            (BudgetShare.GlobalLimitReached, _, _) => CapacityLimit.GlobalRequestsPerMinute,
            (_, BudgetShare.ClientLimitReached, _) => CapacityLimit.ClientRequestsPerDay,
            (_, BudgetShare.GlobalLimitReached, _) => CapacityLimit.GlobalRequestsPerDay,
            (_, _, BudgetShare.ClientLimitReached) => CapacityLimit.ClientInputTokensPerMinute,
            (_, _, BudgetShare.GlobalLimitReached) => CapacityLimit.GlobalInputTokensPerMinute,
            _ when _inFlight >= _maxConcurrentCalls => CapacityLimit.GlobalConcurrency,
            _ when client.InFlight >= _clientMaxConcurrentCalls => CapacityLimit.ClientConcurrency,
            _ => CapacityLimit.None,
        };

        if (limit != CapacityLimit.None)
        {
            var warn = client.WarnedAt is not { } warnedAt || now - warnedAt >= _minute;
            client.WarnedAt = warn ? now : client.WarnedAt;
            var result = limit is CapacityLimit.GlobalConcurrency or CapacityLimit.ClientConcurrency
                ? AdmissionResult.ConcurrencyExceeded
                : AdmissionResult.CapacityExceeded;
            return new Decision(result, limit, warn);
        }

        // Guaranteed only if every budget admits from the client's reservation; otherwise it used the shared remainder.
        var guaranteed = minute == BudgetShare.Guaranteed && day == BudgetShare.Guaranteed && tokens == BudgetShare.Guaranteed;
        _perMinute.Record(clientId, now);
        _perDay.Record(clientId, now);
        _inputTokensPerMinute.Record(clientId, now, inputTokens);
        _inFlight++;
        client.InFlight++;
        return new Decision(guaranteed ? AdmissionResult.Guaranteed : AdmissionResult.Shared, CapacityLimit.None, Warn: false);
    }

    private void Release(ClientState client)
    {
        lock (_lock)
        {
            _inFlight--;
            client.InFlight--;
        }
    }

    private void Count(AdmissionResult result) =>
        _admissions.Add(1, new KeyValuePair<string, object?>(ResultTag, result switch
        {
            AdmissionResult.Guaranteed => "guaranteed",
            AdmissionResult.Shared => "shared",
            AdmissionResult.NotNeeded => "not_needed",
            AdmissionResult.ConcurrencyExceeded => "concurrency_exceeded",
            _ => "capacity_exceeded",
        }));

    [LoggerMessage(
        EventId = 1200,
        EventName = "AiCapacityRefused",
        Level = LogLevel.Warning,
        Message = "AI capacity refused an AI analysis call for client {ClientId}: {CapacityLimit} reached. The input is held for review; further refusals for this client are not logged for a minute")]
    private static partial void LogRefused(ILogger logger, string clientId, CapacityLimit capacityLimit);

    [LoggerMessage(
        EventId = 1201,
        EventName = "AiCapacityUnknownClient",
        Level = LogLevel.Warning,
        Message = "AI capacity refused an AI analysis call for a client that is not a configured analysis client. The input is held for review; further such refusals are not logged for a minute")]
    private static partial void LogUnknownClientRefused(ILogger logger);

    /// <summary>The fixed vocabulary of the admissions metric (bounded tag values).</summary>
    private enum AdmissionResult
    {
        Guaranteed = 1,
        Shared = 2,
        NotNeeded = 3,
        CapacityExceeded = 4,
        ConcurrencyExceeded = 5,
    }

    private readonly record struct Decision(AdmissionResult Result, CapacityLimit Limit, bool Warn);

    /// <summary>Mutable per-client state, guarded by <see cref="_lock"/>.</summary>
    private sealed class ClientState
    {
        public int InFlight { get; set; }

        public long? WarnedAt { get; set; }
    }
}

/// <summary>The limit that refused an AI call. Internal detail: logged, never returned to a client.</summary>
internal enum CapacityLimit
{
    None = 0,
    GlobalRequestsPerMinute = 1,
    GlobalRequestsPerDay = 2,
    ClientRequestsPerMinute = 3,
    ClientRequestsPerDay = 4,
    GlobalConcurrency = 5,
    ClientConcurrency = 6,
    UnknownClient = 7,
    GlobalInputTokensPerMinute = 8,
    ClientInputTokensPerMinute = 9,
}
