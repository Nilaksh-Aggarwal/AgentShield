using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Domain.Policy;
using AgentShield.Infrastructure.AiCapacity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AgentShield.UnitTests.Infrastructure.AiCapacity;

/// <summary>
/// The in-memory AI capacity gate with a manual clock: global and per-client rolling budgets, guaranteed shares,
/// concurrency without a queue, the Block skip, bounded state, metrics and throttled warnings.
/// </summary>
public sealed class InMemoryAiCapacityGateTests : IDisposable
{
    private const string A = "client-a";
    private const string B = "client-b";
    private const string C = "client-c";

    private static readonly TimeSpan Minute = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan Day = TimeSpan.FromDays(1);
    private static readonly TimeSpan Tick = TimeSpan.FromTicks(1);

    private readonly ManualClock _clock = new();
    private readonly TestMeterFactory _meters = new();
    private readonly RecordingLogger<InMemoryAiCapacityGate> _logger = new();

    public void Dispose() => _meters.Dispose();

    // ── Global requests per minute ──────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void TryAdmit_GlobalPerMinute_AdmitsEveryCallUpToTheLimit()
    {
        string[] clients = ["c1", "c2", "c3", "c4", "c5"];
        var gate = Gate(clients: clients);

        var results = clients.SelectMany(client => new[] { Call(gate, client), Call(gate, client) }).ToArray();

        Assert.Equal(10, results.Length);
        Assert.All(results, status => Assert.Equal(AiAdmissionStatus.Admitted, status));
    }

    [Fact]
    public void TryAdmit_GlobalPerMinute_RefusesEveryClientOnceTheLimitIsReached()
    {
        string[] clients = ["c1", "c2", "c3", "c4", "c5"];
        var gate = Gate(clients: clients);
        foreach (var client in clients)
        {
            Call(gate, client);
            Call(gate, client);
        }

        // Each client is still below its own maximum (4): the global limit (10) refuses them.
        Assert.All(clients, client => Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, client)));
        Assert.Contains(_logger.Entries, entry => entry.Properties["CapacityLimit"] == nameof(CapacityLimit.GlobalRequestsPerMinute));
    }

    [Fact]
    public void TryAdmit_GlobalPerMinute_IsARollingWindow_NoDoubleBurstAcrossAMinuteBoundary()
    {
        string[] clients = ["c1", "c2", "c3", "c4", "c5"];
        var gate = Gate(clients: clients);
        _clock.Advance(TimeSpan.FromSeconds(59.5));
        foreach (var client in clients)
        {
            Call(gate, client);
            Call(gate, client);
        }

        // One second later the clock minute has changed; a fixed window would allow ten more here.
        _clock.Advance(TimeSpan.FromSeconds(1));

        Assert.All(clients, client => Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, client)));
    }

    [Fact]
    public void TryAdmit_MinuteWindow_FreesEachCallExactlyOneMinuteAfterItWasAdmitted()
    {
        var gate = Gate();
        Repeat(4, () => Call(gate, A));
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A));

        _clock.Advance(Minute - Tick);
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A));

        _clock.Advance(Tick);
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A));
    }

    // ── Global requests per day ─────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void TryAdmit_GlobalPerDay_RefusesOnceTheDailyBudgetIsSpent_EvenWithMinuteCapacityLeft()
    {
        var gate = Gate(options => (options.GlobalRequestsPerDay, options.DefaultClient!.GuaranteedPerDay, options.DefaultClient.MaxPerDay) = (5, 1, 5));

        // a: 4 (its guarantee plus the remainder, leaving b's daily guarantee of 1), b: 1. Spread out, so no minute limit applies.
        foreach (var client in new[] { A, A, A, A, B })
        {
            Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, client));
            _clock.Advance(Minute);
        }

        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A));
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, B));
        Assert.Contains(_logger.Entries, entry => entry.Properties["CapacityLimit"] == nameof(CapacityLimit.GlobalRequestsPerDay));
    }

    [Fact]
    public void TryAdmit_DayWindow_IsRolling24Hours_NotReset_AtUtcMidnight()
    {
        var gate = Gate(options => (options.DefaultClient!.GuaranteedPerDay, options.DefaultClient.MaxPerDay) = (2, 2));
        Call(gate, A);
        Call(gate, A);
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A));

        // The clock starts at 23:59 UTC: two minutes later it is a new calendar day, and the budget is still spent.
        _clock.Advance(TimeSpan.FromMinutes(2));
        Assert.NotEqual(ManualClock.Start.Date, _clock.GetUtcNow().Date);
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A));
        Assert.Contains(_logger.Entries, entry => entry.Properties["CapacityLimit"] == nameof(CapacityLimit.ClientRequestsPerDay));

        _clock.Advance(Day - TimeSpan.FromMinutes(2) - Tick);
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A));

        _clock.Advance(Tick);
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A));
    }

    [Fact]
    public void TryAdmit_OneClient_CannotSpendTheWholeDailyBudget_TheOthersDailyGuaranteeStays()
    {
        var gate = Gate(options => (options.GlobalRequestsPerDay, options.DefaultClient!.GuaranteedPerDay, options.DefaultClient.MaxPerDay) = (10, 3, 10));

        var admittedForA = 0;
        while (Call(gate, A) == AiAdmissionStatus.Admitted)
        {
            admittedForA++;
            _clock.Advance(Minute);
        }

        Assert.Equal(7, admittedForA);
        Repeat(3, () => Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, B)));
    }

    // ── Per-client shares ───────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void TryAdmit_GuaranteedShare_IsProtected_AgainstAClientThatTriesToTakeEverything()
    {
        var gate = Gate(options => options.DefaultClient!.MaxPerMinute = 10);

        var admittedForA = 0;
        while (Call(gate, A) == AiAdmissionStatus.Admitted)
        {
            admittedForA++;
        }

        // 10 globally, 2 reserved for b: a stops at 8 although its own maximum is 10.
        Assert.Equal(8, admittedForA);
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, B));
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, B));
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, B));
    }

    [Fact]
    public void TryAdmit_ClientsThatHaveNeverCalled_KeepTheirGuarantee()
    {
        var gate = Gate(options => options.DefaultClient!.MaxPerMinute = 10, clients: [A, B, C]);

        Repeat(10, () => Call(gate, A));

        // b and c never called before a tried to take everything; both still get their two.
        Assert.Equal([AiAdmissionStatus.Admitted, AiAdmissionStatus.Admitted], [Call(gate, B), Call(gate, B)]);
        Assert.Equal([AiAdmissionStatus.Admitted, AiAdmissionStatus.Admitted], [Call(gate, C), Call(gate, C)]);
        Assert.All([A, B, C], client => Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, client)));
    }

    [Fact]
    public void TryAdmit_AfterItsGuarantee_AClientUsesTheSharedRemainder()
    {
        using var metrics = _meters.Record(InMemoryAiCapacityGate.AdmissionsInstrument, InMemoryAiCapacityGate.ResultTag);
        var gate = Gate();

        Repeat(4, () => Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A)));

        Assert.Equal(new Dictionary<string, int> { ["guaranteed"] = 2, ["shared"] = 2 }, metrics.CountsByTag());
    }

    [Fact]
    public void TryAdmit_ClientMaxPerMinute_IsEnforced_WhileGlobalCapacityRemains()
    {
        var gate = Gate();

        Repeat(4, () => Call(gate, A));

        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A));
        Assert.Equal("ClientRequestsPerMinute", Assert.Single(_logger.Entries).Properties["CapacityLimit"]);
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, B));
    }

    // ── Concurrency ─────────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void TryAdmit_GlobalConcurrency_IsEnforced_AndAReleaseFreesASlot()
    {
        var gate = Gate(options => options.MaxConcurrentCalls = 2, clients: [A, B, C]);
        using var first = gate.TryAdmit(Request(A));
        var second = gate.TryAdmit(Request(B));

        Assert.Equal(AiAdmissionStatus.ConcurrencyExceeded, Call(gate, C));
        Assert.Equal("GlobalConcurrency", Assert.Single(_logger.Entries).Properties["CapacityLimit"]);

        second.Dispose();
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, C));
    }

    [Fact]
    public void TryAdmit_ClientConcurrency_IsEnforced_WithoutAffectingOtherClients()
    {
        var gate = Gate(options => options.DefaultClient!.MaxConcurrentCalls = 1);
        using var held = gate.TryAdmit(Request(A));

        Assert.Equal(AiAdmissionStatus.ConcurrencyExceeded, Call(gate, A));
        Assert.Equal("ClientConcurrency", Assert.Single(_logger.Entries).Properties["CapacityLimit"]);
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, B));
    }

    [Fact]
    public async Task TryAdmit_UnderContention_NeverQueues_AndNeverAdmitsMoreThanTheConcurrencyLimit()
    {
        string[] clients = ["c1", "c2", "c3", "c4", "c5"];
        var gate = Gate(options => (options.GlobalRequestsPerMinute, options.GlobalRequestsPerDay) = (1000, 1000), clients: clients);
        using var start = new ManualResetEventSlim();

        var attempts = Enumerable.Range(0, 64).Select(index => Task.Run(() =>
        {
            start.Wait(TimeSpan.FromSeconds(10));
            return gate.TryAdmit(Request(clients[index % clients.Length]));
        })).ToArray();
        start.Set();
        var admissions = await Task.WhenAll(attempts).WaitAsync(TimeSpan.FromSeconds(10));

        // Nobody released anything, so nobody could have been admitted by waiting: 4 global slots, the rest refused at once.
        Assert.Equal(4, admissions.Count(admission => admission.Status == AiAdmissionStatus.Admitted));
        Assert.Equal(60, admissions.Count(admission => admission.Status == AiAdmissionStatus.ConcurrencyExceeded));
        Assert.Equal(4, gate.InFlight);
        foreach (var admission in admissions)
        {
            admission.Dispose();
        }

        Assert.Equal(0, gate.InFlight);
    }

    [Fact]
    public void Release_ReturnsOnlyTheConcurrencySlot_OnlyOnce_AndNeverRefundsTheRequestBudget()
    {
        var gate = Gate();
        var first = gate.TryAdmit(Request(A));
        using var second = gate.TryAdmit(Request(A));
        Assert.Equal(AiAdmissionStatus.ConcurrencyExceeded, Call(gate, A));

        first.Dispose();
        first.Dispose();

        // One slot back (not two): one more concurrent call for a, then the concurrency limit again.
        using var third = gate.TryAdmit(Request(A));
        Assert.Equal(AiAdmissionStatus.Admitted, third.Status);
        Assert.Equal(2, gate.InFlight);

        // Three calls were admitted this minute; a finished call still counts against a's per-minute maximum (4).
        third.Dispose();
        second.Dispose();
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A));
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A));
    }

    // ── Deterministic Block ─────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void TryAdmit_DeterministicBlock_IsNotNeeded_AndConsumesNothing()
    {
        using var metrics = _meters.Record(InMemoryAiCapacityGate.AdmissionsInstrument, InMemoryAiCapacityGate.ResultTag);
        var gate = Gate(options => options.DefaultClient!.MaxConcurrentCalls = 1);

        Repeat(50, () => Assert.Equal(AiAdmissionStatus.NotNeeded, Call(gate, A, SecurityDecision.Block)));
        using var held = gate.TryAdmit(Request(A, SecurityDecision.Block));

        Assert.Equal(AiAdmissionStatus.NotNeeded, held.Status);
        Assert.Equal(0, gate.InFlight);
        held.Dispose();
        Repeat(4, () => Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A)));
        Assert.Equal(51, metrics.CountsByTag()["not_needed"]);
        Assert.Empty(_logger.Entries);
    }

    [Theory]
    [InlineData(SecurityDecision.Allow)]
    [InlineData(SecurityDecision.Review)]
    public void TryAdmit_DeterministicAllowOrReview_IsEligible(SecurityDecision decision) =>
        Assert.Equal(AiAdmissionStatus.Admitted, Call(Gate(), A, decision));

    [Fact]
    public void TryAdmit_SkipDisabled_AdmitsADeterministicBlockLikeAnyOtherCall()
    {
        var gate = Gate(options => options.SkipWhenDeterministicBlock = false);

        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A, SecurityDecision.Block));
    }

    // ── State, identity, metrics, logs ──────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void TryAdmit_UnknownClient_IsRefusedAndNeverStored_SoNoKeyOrCallerValueEntersTheState()
    {
        const string ApiKeyLookalike = "test-analyzer-key-0123456789abcdefghijklmnop";
        var gate = Gate();

        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, ApiKeyLookalike));
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, string.Empty));
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A.ToUpperInvariant()));

        Assert.Equal([A, B], gate.TrackedClientIds.Order(StringComparer.Ordinal));
        Assert.Equal(0, gate.InFlight);
        var warning = Assert.Single(_logger.Entries);
        Assert.Equal(1201, warning.EventId.Id);
        Assert.DoesNotContain(ApiKeyLookalike, _logger.AllText(), StringComparison.Ordinal);
    }

    [Fact]
    public void TryAdmit_EveryDecision_IsCountedWithOneBoundedResultTag()
    {
        using var metrics = _meters.Record(InMemoryAiCapacityGate.AdmissionsInstrument, InMemoryAiCapacityGate.ResultTag);
        var gate = Gate();

        Repeat(4, () => Call(gate, A));
        Call(gate, A);
        Call(gate, "not-a-client");
        Call(gate, B, SecurityDecision.Block);
        using (gate.TryAdmit(Request(B)))
        using (gate.TryAdmit(Request(B)))
        {
            Call(gate, B);
        }

        Assert.Equal(
            new Dictionary<string, int>
            {
                ["guaranteed"] = 4,
                ["shared"] = 2,
                ["capacity_exceeded"] = 2,
                ["not_needed"] = 1,
                ["concurrency_exceeded"] = 1,
            },
            metrics.CountsByTag());
        Assert.Equal([InMemoryAiCapacityGate.ResultTag], metrics.TagKeys());
    }

    [Fact]
    public void TryAdmit_Refusals_AreLoggedAtMostOncePerClientPerMinute_WithNoValuesBeyondClientAndLimit()
    {
        var gate = Gate(options => (options.DefaultClient!.GuaranteedPerDay, options.DefaultClient.MaxPerDay) = (2, 2));
        Repeat(2, () => Call(gate, A));
        Repeat(2, () => Call(gate, B));

        Repeat(5, () => Call(gate, A));
        Repeat(5, () => Call(gate, B));
        Assert.Equal(2, _logger.Entries.Count);

        _clock.Advance(Minute - Tick);
        Call(gate, A);
        Assert.Equal(2, _logger.Entries.Count);

        _clock.Advance(Tick);
        Call(gate, A);
        Assert.Equal(3, _logger.Entries.Count);

        Assert.All(_logger.Entries, entry =>
        {
            Assert.Equal(LogLevel.Warning, entry.Level);
            Assert.Equal(1200, entry.EventId.Id);
            Assert.Equal(["CapacityLimit", "ClientId", "{OriginalFormat}"], entry.Properties.Keys.Order(StringComparer.Ordinal));
        });
        Assert.Equal([A, B, A], _logger.Entries.Select(entry => entry.Properties["ClientId"]));
    }

    [Fact]
    public void TryAdmit_RefusalWarnings_AreThrottledToOnePerMinute_WhateverTheClockReads()
    {
        // Production timestamps are large numbers, not 0: the throttle must compare elapsed time. (Mutation testing: with the
        // test clock at 0, an addition in place of the subtraction, and a timestamp renewed on every refusal, survived.)
        _clock.Advance(TimeSpan.FromDays(3));
        var gate = Gate(options => (options.DefaultClient!.GuaranteedPerDay, options.DefaultClient.MaxPerDay) = (1, 1));
        Call(gate, A);
        void RefuseBoth()
        {
            Call(gate, "unknown-client");
            Call(gate, A);
        }

        RefuseBoth(); // the first refusals: one warning each
        _clock.Advance(TimeSpan.FromSeconds(30));
        RefuseBoth(); // throttled
        _clock.Advance(TimeSpan.FromSeconds(30) - Tick);
        RefuseBoth(); // a tick short of a minute after the first warnings: still throttled
        _clock.Advance(Tick);
        RefuseBoth(); // a minute after the first warnings: warned again

        Assert.Equal([1201, 1200, 1201, 1200], _logger.Entries.Select(entry => entry.EventId.Id));
    }

    [Fact]
    public void Gate_IsProviderAgnostic_TheInfrastructureAssemblyReferencesNoAiProvider()
    {
        var references = typeof(InMemoryAiCapacityGate).Assembly.GetReferencedAssemblies().Select(assembly => assembly.Name ?? string.Empty).ToArray();

        Assert.DoesNotContain("AgentShield.AI", references);
        Assert.DoesNotContain(references, name => name.Contains("Google", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(InMemoryAiCapacityGate.AdmissionsInstrument)]
    [InlineData(InMemoryAiCapacityGate.TokenAdmissionsInstrument)]
    [InlineData(InMemoryAiCapacityGate.ReservedInputTokensInstrument)]
    public void TryAdmit_MetricsListenerThrows_TheConcurrencySlotIsReleased_AndTheNextCallIsAdmitted(string instrument)
    {
        // Regression (H-05): the slot was taken under the lock and the metrics were recorded before the admission that
        // releases it existed, so a throwing listener left the slot taken for good. Observability must never change
        // resource accounting: the call fails (the analysis fails closed), and the slot is free again.
        var gate = Gate(options => options.DefaultClient!.MaxConcurrentCalls = 1);
        using (_meters.ThrowOn(instrument))
        {
            Repeat(3, () => Assert.Throws<InvalidOperationException>(() => gate.TryAdmit(Request(A))));
        }

        Assert.Equal(0, gate.InFlight);
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A));
    }

    [Fact]
    public void Gate_WithMissingSettings_RefusesEverything_InsteadOfInventingABudget()
    {
        // Only reachable with AI disabled (startup validation stops an enabled application with missing settings).
        var gate = new InMemoryAiCapacityGate(Options.Create(new AiCapacityOptions()), new StaticClientDirectory(A), _clock, _meters, _logger);

        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A));
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A, SecurityDecision.Block));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────────────────────────────────────────

    /// <summary>The committed defaults (10/min, 400/day, 4 concurrent; per client 2–4/min, 80–160/day, 2 concurrent).</summary>
    internal static AiCapacityOptions DefaultOptions() => new()
    {
        GlobalRequestsPerMinute = 10,
        GlobalRequestsPerDay = 400,
        MaxConcurrentCalls = 4,
        GlobalInputTokensPerMinute = 200_000,
        SkipWhenDeterministicBlock = true,
        DefaultClient = new AiClientCapacityOptions
        {
            GuaranteedPerMinute = 2,
            MaxPerMinute = 4,
            GuaranteedPerDay = 80,
            MaxPerDay = 160,
            MaxConcurrentCalls = 2,
            GuaranteedInputTokensPerMinute = 40_000,
            MaxInputTokensPerMinute = 80_000,
            WhenExceeded = AiCapacityExceededAction.Review,
        },
    };

    private InMemoryAiCapacityGate Gate(Action<AiCapacityOptions>? configure = null, string[]? clients = null)
    {
        var options = DefaultOptions();
        configure?.Invoke(options);
        return new InMemoryAiCapacityGate(Options.Create(options), new StaticClientDirectory(clients ?? [A, B]), _clock, _meters, _logger);
    }

    /// <summary>A request with a small token estimate, so the token budget never binds unless a test says so.</summary>
    internal static AiAdmissionRequest Request(string clientId, SecurityDecision decision = SecurityDecision.Allow, long inputTokens = 1_000) =>
        new(clientId, decision, inputTokens);

    /// <summary>One AI call that is admitted (or not) and, if admitted, finishes at once.</summary>
    private static AiAdmissionStatus Call(InMemoryAiCapacityGate gate, string clientId, SecurityDecision decision = SecurityDecision.Allow)
    {
        using var admission = gate.TryAdmit(Request(clientId, decision));
        return admission.Status;
    }

    private static void Repeat(int times, Action action)
    {
        for (var index = 0; index < times; index++)
        {
            action();
        }
    }
}
