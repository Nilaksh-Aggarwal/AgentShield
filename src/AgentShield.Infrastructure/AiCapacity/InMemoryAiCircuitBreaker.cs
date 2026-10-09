using System.Diagnostics.Metrics;
using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Domain.SecurityEvents;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AgentShield.Infrastructure.AiCapacity;

/// <summary>States of the AI provider circuit.</summary>
internal enum AiCircuitState
{
    /// <summary>Calls are allowed; consecutive availability failures are counted.</summary>
    Closed = 1,

    /// <summary>No call is allowed until the open period has elapsed.</summary>
    Open = 2,

    /// <summary>Exactly one probe call at a time; its outcome closes or reopens the circuit.</summary>
    HalfOpen = 3,
}

/// <summary>
/// In-process <see cref="IAiCircuitBreaker"/>: one circuit for the configured AI provider and model, shared by every
/// request and client in the process (docs/security/ai-analysis.md, section 17).
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><b>Closed → Open</b> after <c>FailureThreshold</c> consecutive availability failures
/// (<see cref="AiProviderAvailability.IsAvailabilityFailure"/>). Any call in which the provider answered resets the count.
/// Outcomes of calls started before the circuit last left the closed state are ignored.</item>
/// <item><b>Open → HalfOpen</b> once <c>OpenDurationSeconds</c> have elapsed, checked lazily by the next caller on the
/// monotonic <see cref="TimeProvider"/> clock (no timer).</item>
/// <item><b>HalfOpen:</b> the first caller gets the only probe permit (bounded by <c>HalfOpenProbeTimeoutSeconds</c>);
/// everyone else is refused. Probe answered → <b>Closed</b>; probe availability failure → <b>Open</b> for a new period;
/// probe released without an outcome (no call made, e.g. capacity refused, or cancelled) → the slot is free again. A probe
/// that reports nothing within its timeout plus one second of grace counts as failed (<b>Open</b>), so the circuit
/// cannot stay half-open behind a lost probe.</item>
/// </list>
/// <para>State is a handful of fields under one lock: bounded, created once, and keyed by nothing a client controls.
/// Decisions never wait. Transitions are logged (EventId 1300; at most a few per open period) and counted; nothing about
/// requests, content, answers or keys is logged or tagged.</para>
/// </remarks>
internal sealed partial class InMemoryAiCircuitBreaker : IAiCircuitBreaker
{
    public const string TransitionsInstrument = "agentshield.ai.circuit.transitions";
    public const string RejectionsInstrument = "agentshield.ai.circuit.rejections";
    public const string ProbesInstrument = "agentshield.ai.circuit.probes";
    public const string ProviderFailuresInstrument = "agentshield.ai.provider.failures";

    private static readonly TimeSpan ProbeGrace = TimeSpan.FromSeconds(1);

    private readonly Lock _lock = new();
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<InMemoryAiCircuitBreaker> _logger;
    private readonly bool _enabled;
    private readonly int _failureThreshold;
    private readonly long _openDuration;
    private readonly TimeSpan _probeTimeout;
    private readonly long _probeExpiry;
    private readonly Counter<long> _transitions;
    private readonly Counter<long> _rejections;
    private readonly Counter<long> _probes;
    private readonly Counter<long> _providerFailures;

    private AiCircuitState _state = AiCircuitState.Closed;
    private int _consecutiveFailures;
    private long _openedAt;
    private long _closedGeneration;
    private long _probeId;
    private bool _probeInFlight;
    private long _probeStartedAt;

    public InMemoryAiCircuitBreaker(
        IOptions<AiCircuitBreakerOptions> options,
        TimeProvider timeProvider,
        IMeterFactory meterFactory,
        ILogger<InMemoryAiCircuitBreaker> logger)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(meterFactory);
        ArgumentNullException.ThrowIfNull(logger);

        // Startup validation guarantees complete settings whenever AI is enabled. With AI disabled the breaker is never
        // asked; missing values then mean "no breaker" rather than invented thresholds.
        var settings = options.Value;
        _timeProvider = timeProvider;
        _logger = logger;
        _enabled = settings.Enabled ?? false;
        _failureThreshold = Math.Max(1, settings.FailureThreshold);
        _openDuration = checked(timeProvider.TimestampFrequency * Math.Max(1, settings.OpenDurationSeconds));
        _probeTimeout = TimeSpan.FromSeconds(Math.Max(1, settings.HalfOpenProbeTimeoutSeconds));
        _probeExpiry = checked((long)((_probeTimeout + ProbeGrace).TotalSeconds * timeProvider.TimestampFrequency));

        var meter = meterFactory.Create(InMemoryAiCapacityGate.MeterName);
        _transitions = meter.CreateCounter<long>(TransitionsInstrument, unit: "{transition}", description: "AI circuit state transitions, by from and to state.");
        _rejections = meter.CreateCounter<long>(RejectionsInstrument, unit: "{call}", description: "AI calls refused by the circuit breaker, by state.");
        _probes = meter.CreateCounter<long>(ProbesInstrument, unit: "{probe}", description: "Half-open probe calls, by result.");
        _providerFailures = meter.CreateCounter<long>(ProviderFailuresInstrument, unit: "{failure}", description: "AI provider availability failures, by kind.");
    }

    /// <summary>The current state (tests). Does not advance the open period; <see cref="TryAcquire"/> does.</summary>
    internal AiCircuitState State
    {
        get
        {
            lock (_lock)
            {
                return _state;
            }
        }
    }

    public AiCircuitPermit TryAcquire()
    {
        if (!_enabled)
        {
            return AiCircuitPermit.Allowed(CountFailure, static () => { });
        }

        List<Transition>? transitions = null;
        AiCircuitPermit permit;
        string? rejectedIn = null;
        string? probeEvent = null;
        lock (_lock)
        {
            var now = _timeProvider.GetTimestamp();
            if (_state == AiCircuitState.Open && now - _openedAt >= _openDuration)
            {
                Move(AiCircuitState.HalfOpen, "OpenPeriodElapsed", ref transitions);
            }

            if (_state == AiCircuitState.HalfOpen && _probeInFlight && now - _probeStartedAt >= _probeExpiry)
            {
                _probeInFlight = false;
                probeEvent = "expired";
                Open(now, "ProbeExpired", ref transitions);
            }

            switch (_state)
            {
                case AiCircuitState.Closed:
                    var generation = _closedGeneration;
                    permit = AiCircuitPermit.Allowed(status => OnCallReported(generation, status), static () => { });
                    break;

                case AiCircuitState.HalfOpen when !_probeInFlight:
                    var probe = ++_probeId;
                    _probeInFlight = true;
                    _probeStartedAt = now;
                    probeEvent = "started";
                    permit = AiCircuitPermit.Probe(_probeTimeout, status => OnProbeReported(probe, status), () => OnProbeAbandoned(probe));
                    break;

                default:
                    rejectedIn = _state == AiCircuitState.Open ? "open" : "half_open";
                    permit = AiCircuitPermit.Rejected;
                    break;
            }
        }

        // Metrics and logs after the decision. If one of them throws (a failing metrics listener), a probe slot taken above
        // goes back before the exception leaves: observability never changes the circuit's accounting.
        try
        {
            if (probeEvent is not null)
            {
                _probes.Add(1, new KeyValuePair<string, object?>("result", probeEvent));
            }

            if (rejectedIn is not null)
            {
                _rejections.Add(1, new KeyValuePair<string, object?>("state", rejectedIn));
            }

            Emit(transitions);
        }
        catch
        {
            permit.Dispose();
            throw;
        }

        return permit;
    }

    /// <summary>A normal call (issued while closed) ended.</summary>
    private void OnCallReported(long generation, AiAnalysisStatus status)
    {
        var failed = AiProviderAvailability.IsAvailabilityFailure(status);
        List<Transition>? transitions = null;
        if (failed || AiProviderAvailability.ProviderResponded(status))
        {
            lock (_lock)
            {
                // A call started before the circuit last left the closed state says nothing about the current period.
                if (_state == AiCircuitState.Closed && generation == _closedGeneration)
                {
                    if (!failed)
                    {
                        _consecutiveFailures = 0;
                    }
                    else if (++_consecutiveFailures >= _failureThreshold)
                    {
                        Open(_timeProvider.GetTimestamp(), status.ToString(), ref transitions);
                    }
                }
            }
        }

        // After the state change, so a failing metrics listener cannot stop a failure from counting.
        CountFailure(status);
        Emit(transitions);
    }

    /// <summary>The half-open probe ended with an outcome.</summary>
    private void OnProbeReported(long probe, AiAnalysisStatus status)
    {
        List<Transition>? transitions = null;
        string result;
        lock (_lock)
        {
            if (_state != AiCircuitState.HalfOpen || !_probeInFlight || probe != _probeId)
            {
                result = string.Empty;
            }
            else
            {
                _probeInFlight = false;
                result = Resolve(status, ref transitions);
            }
        }

        // After the state change, so a failing metrics listener cannot keep a failed probe from reopening the circuit.
        CountFailure(status);
        if (result.Length > 0)
        {
            _probes.Add(1, new KeyValuePair<string, object?>("result", result));
        }

        Emit(transitions);
    }

    /// <summary>Applies the current probe's outcome. Runs under <see cref="_lock"/>.</summary>
    private string Resolve(AiAnalysisStatus status, ref List<Transition>? transitions)
    {
        if (AiProviderAvailability.IsAvailabilityFailure(status))
        {
            Open(_timeProvider.GetTimestamp(), status.ToString(), ref transitions);
            return "failed";
        }

        if (AiProviderAvailability.ProviderResponded(status))
        {
            _consecutiveFailures = 0;
            _closedGeneration++;
            Move(AiCircuitState.Closed, "ProbeSucceeded", ref transitions);
            return "succeeded";
        }

        return "abandoned";
    }

    /// <summary>The half-open probe permit was released without an outcome: free the slot for the next caller.</summary>
    private void OnProbeAbandoned(long probe)
    {
        lock (_lock)
        {
            if (_state != AiCircuitState.HalfOpen || !_probeInFlight || probe != _probeId)
            {
                return;
            }

            _probeInFlight = false;
        }

        _probes.Add(1, new KeyValuePair<string, object?>("result", "abandoned"));
    }

    /// <summary>Opens the circuit for a new period. Runs under <see cref="_lock"/>.</summary>
    private void Open(long now, string reason, ref List<Transition>? transitions)
    {
        _openedAt = now;
        _consecutiveFailures = 0;
        _closedGeneration++;
        Move(AiCircuitState.Open, reason, ref transitions);
    }

    /// <summary>Changes the state and records the transition for logging after the lock. Runs under <see cref="_lock"/>.</summary>
    private void Move(AiCircuitState to, string reason, ref List<Transition>? transitions)
    {
        (transitions ??= []).Add(new Transition(_state, to, reason));
        _state = to;
    }

    private void Emit(List<Transition>? transitions)
    {
        if (transitions is null)
        {
            return;
        }

        foreach (var transition in transitions)
        {
            _transitions.Add(
                1,
                new KeyValuePair<string, object?>("from", Tag(transition.From)),
                new KeyValuePair<string, object?>("to", Tag(transition.To)));
            LogTransition(
                _logger,
                transition.To == AiCircuitState.Open ? LogLevel.Warning : LogLevel.Information,
                transition.From,
                transition.To,
                transition.Reason);
        }
    }

    private void CountFailure(AiAnalysisStatus status)
    {
        var kind = status switch
        {
            AiAnalysisStatus.RateLimited => "rate_limited",
            AiAnalysisStatus.Unavailable => "unavailable",
            AiAnalysisStatus.NetworkFailure => "network_failure",
            AiAnalysisStatus.TimedOut => "timed_out",
            _ => null,
        };

        if (kind is not null)
        {
            _providerFailures.Add(1, new KeyValuePair<string, object?>("kind", kind));
        }
    }

    private static string Tag(AiCircuitState state) => state switch
    {
        AiCircuitState.Closed => "closed",
        AiCircuitState.Open => "open",
        _ => "half_open",
    };

    // Fixed vocabulary only: states and a reason (an AiAnalysisStatus name or a fixed word). Never content or errors.
    [LoggerMessage(
        EventId = 1300,
        EventName = "AiCircuitTransition",
        Message = "AI provider circuit {FromState} -> {ToState} ({CircuitReason})")]
    private static partial void LogTransition(ILogger logger, LogLevel level, AiCircuitState fromState, AiCircuitState toState, string circuitReason);

    private readonly record struct Transition(AiCircuitState From, AiCircuitState To, string Reason);
}
