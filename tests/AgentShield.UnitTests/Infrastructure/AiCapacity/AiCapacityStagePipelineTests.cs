using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Abstractions.Context;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Application.Common.Results;
using AgentShield.Domain.Policy;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Domain.Threats;
using AgentShield.Infrastructure.AiCapacity;
using AgentShield.Security.AiAnalysis;
using AgentShield.Security.Policy;
using AgentShield.Security.Risk;
using Microsoft.Extensions.Options;

namespace AgentShield.UnitTests.Infrastructure.AiCapacity;

/// <summary>
/// The real AI stage (Security) with the real in-memory gate (Infrastructure), the real risk and policy engines and a
/// scripted provider: capacity is released however the provider call ends, a deterministic Block uses none, and an
/// exhausted budget holds the input for review without calling the provider.
/// </summary>
public sealed class AiCapacityStagePipelineTests : IDisposable
{
    private const string Client = "client-a";

    private static readonly NormalizedInput Input = new("What is the capital of France?", "What is the capital of France?");

    private static readonly ThreatFinding DeterministicHigh = new(
        "InstructionOverride.IgnorePrevious", ThreatCategory.InstructionOverride, ThreatSeverity.High, 0.9,
        "Fixed description.", new FindingEvidence("InstructionOverride", "IO-001", 1));

    private static readonly ThreatFinding DeterministicMedium = new(
        "InstructionOverride.NewInstructions", ThreatCategory.InstructionOverride, ThreatSeverity.Medium, 0.6,
        "Fixed description.", new FindingEvidence("InstructionOverride", "IO-002", 1));

    private readonly ManualClock _clock = new();
    private readonly TestMeterFactory _meters = new();

    public void Dispose() => _meters.Dispose();

    [Fact]
    public async Task AnalyzeAsync_AfterTheProviderAnswers_TheConcurrencySlotIsFreeForTheNextCall()
    {
        var gate = Gate(options => options.DefaultClient!.MaxConcurrentCalls = 1);
        var provider = new CountingProvider((_, _) => Task.FromResult(Result.Success(new AiAnalysisOutput([]))));

        var first = await Stage(gate, provider).AnalyzeAsync(Input, [], CancellationToken.None);
        var second = await Stage(gate, provider).AnalyzeAsync(Input, [], CancellationToken.None);

        Assert.Equal([AiAnalysisStatus.Completed, AiAnalysisStatus.Completed], [first.Summary.Status, second.Summary.Status]);
        Assert.Equal(2, provider.Calls);
        Assert.Equal(0, gate.InFlight);
    }

    [Fact]
    public async Task AnalyzeAsync_AfterTheProviderFails_TheConcurrencySlotIsFreeForTheNextCall()
    {
        var gate = Gate(options => options.DefaultClient!.MaxConcurrentCalls = 1);
        var provider = new CountingProvider((_, _) => Task.FromResult(Result.Failure<AiAnalysisOutput>(AiAnalysisErrors.Unavailable())));

        await Stage(gate, provider).AnalyzeAsync(Input, [], CancellationToken.None);
        var second = await Stage(gate, provider).AnalyzeAsync(Input, [], CancellationToken.None);

        Assert.Equal(AiAnalysisStatus.Unavailable, second.Summary.Status);
        Assert.Equal(2, provider.Calls);
        Assert.Equal(0, gate.InFlight);
    }

    [Fact]
    public async Task AnalyzeAsync_WhileACallIsInFlight_TheNextIsRefusedAtOnce_AndAfterTheTimeoutTheSlotIsFree()
    {
        var gate = Gate(options => options.DefaultClient!.MaxConcurrentCalls = 1);
        var never = new TaskCompletionSource<Result<AiAnalysisOutput>>();
        var provider = new CountingProvider((_, _) => never.Task);

        var pending = Stage(gate, provider).AnalyzeAsync(Input, [], CancellationToken.None);
        Assert.Equal(1, gate.InFlight);

        // No queue: the second analysis does not wait for the first; it is held for review immediately.
        var refused = Stage(gate, provider).AnalyzeAsync(Input, [], CancellationToken.None);
        Assert.True(refused.IsCompletedSuccessfully);
        AssertHeldForReview(await refused, AiAnalysisStatus.CapacityExceeded);
        Assert.Equal(1, provider.Calls);

        _clock.Advance(AiAnalysisLimits.Timeout);
        AssertHeldForReview(await pending.WaitAsync(TimeSpan.FromSeconds(10)), AiAnalysisStatus.TimedOut);
        Assert.Equal(0, gate.InFlight);

        var afterTimeout = Stage(gate, provider).AnalyzeAsync(Input, [], CancellationToken.None);
        Assert.Equal(2, provider.Calls);
        _clock.Advance(AiAnalysisLimits.Timeout);
        await afterTimeout.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task AnalyzeAsync_DeterministicBlocks_CallNoProvider_AndLeaveTheWholeBudget()
    {
        var gate = Gate();
        var provider = new CountingProvider((_, _) => Task.FromResult(Result.Success(new AiAnalysisOutput([]))));

        for (var index = 0; index < 20; index++)
        {
            var outcome = await Stage(gate, provider).AnalyzeAsync(Input, [DeterministicHigh], CancellationToken.None);
            Assert.Equal(AiAnalysisStatus.NotNeeded, outcome.Summary.Status);
            Assert.Empty(outcome.Findings);
        }

        Assert.Equal(0, provider.Calls);
        for (var index = 0; index < 4; index++)
        {
            Assert.Equal(AiAnalysisStatus.Completed, (await Stage(gate, provider).AnalyzeAsync(Input, [], CancellationToken.None)).Summary.Status);
        }
    }

    [Fact]
    public async Task AnalyzeAsync_BudgetExhausted_HoldsTheInputForReview_WithoutCallingTheProvider()
    {
        var gate = Gate();
        var provider = new CountingProvider((_, _) => Task.FromResult(Result.Success(new AiAnalysisOutput([]))));
        for (var index = 0; index < 4; index++)
        {
            await Stage(gate, provider).AnalyzeAsync(Input, [], CancellationToken.None);
        }

        var exhausted = await Stage(gate, provider).AnalyzeAsync(Input, [], CancellationToken.None);

        AssertHeldForReview(exhausted, AiAnalysisStatus.CapacityExceeded);
        Assert.Equal(4, provider.Calls);
    }

    // ── Milestone 6 step 2: circuit breaker and input tokens, with the real gate and breaker ───────────────────────────

    [Fact]
    public async Task AnalyzeAsync_OpenCircuit_HoldsForReview_AndConsumesNoCapacity()
    {
        var gate = Gate();
        var breaker = Breaker();
        var failing = new CountingProvider((_, _) => Task.FromResult(Result.Failure<AiAnalysisOutput>(AiAnalysisErrors.Unavailable())));

        // Three availability failures open the circuit: three of a's four requests this minute are spent.
        for (var index = 0; index < 3; index++)
        {
            AssertHeldForReview(await Stage(gate, failing, breaker).AnalyzeAsync(Input, [], CancellationToken.None), AiAnalysisStatus.Unavailable);
        }

        Assert.Equal(AiCircuitState.Open, breaker.State);
        for (var index = 0; index < 10; index++)
        {
            AssertHeldForReview(await Stage(gate, failing, breaker).AnalyzeAsync(Input, [], CancellationToken.None), AiAnalysisStatus.CircuitOpen);
        }

        Assert.Equal(3, failing.Calls);

        // After the open period the probe is a's fourth request: the ten refused calls consumed nothing.
        _clock.Advance(TimeSpan.FromSeconds(30));
        var healthy = new CountingProvider((_, _) => Task.FromResult(Result.Success(new AiAnalysisOutput([]))));
        var probe = await Stage(gate, healthy, breaker).AnalyzeAsync(Input, [], CancellationToken.None);

        Assert.Equal(AiAnalysisStatus.Completed, probe.Summary.Status);
        Assert.Equal(AiCircuitState.Closed, breaker.State);
        AssertHeldForReview(await Stage(gate, healthy, breaker).AnalyzeAsync(Input, [], CancellationToken.None), AiAnalysisStatus.CapacityExceeded);
    }

    [Fact]
    public async Task AnalyzeAsync_HalfOpen_ManyConcurrentAnalyses_MakeExactlyOneProviderCall()
    {
        var gate = Gate(options => (options.DefaultClient!.MaxPerMinute, options.GlobalRequestsPerMinute) = (10, 10));
        var breaker = Breaker();
        var failing = new CountingProvider((_, _) => Task.FromResult(Result.Failure<AiAnalysisOutput>(AiAnalysisErrors.RateLimited())));
        for (var index = 0; index < 3; index++)
        {
            await Stage(gate, failing, breaker).AnalyzeAsync(Input, [], CancellationToken.None);
        }

        _clock.Advance(TimeSpan.FromSeconds(30));
        var answer = new TaskCompletionSource<Result<AiAnalysisOutput>>();
        var probing = new CountingProvider((_, _) => answer.Task);
        var analyses = Enumerable.Range(0, 8).Select(_ => Stage(gate, probing, breaker).AnalyzeAsync(Input, [], CancellationToken.None)).ToArray();

        // Everyone but the probe is refused at once, without waiting for it.
        Assert.Equal(1, probing.Calls);
        Assert.Equal(7, analyses.Count(analysis => analysis.IsCompletedSuccessfully && analysis.Result.Summary.Status == AiAnalysisStatus.CircuitOpen));

        answer.SetResult(Result.Success(new AiAnalysisOutput([])));
        await Task.WhenAll(analyses).WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(AiCircuitState.Closed, breaker.State);
        Assert.Equal(0, gate.InFlight);
    }

    [Fact]
    public async Task AnalyzeAsync_FailedProbe_HoldsForReview_AndReopensTheCircuit()
    {
        var gate = Gate(options => (options.DefaultClient!.MaxPerMinute, options.GlobalRequestsPerMinute) = (10, 10));
        var breaker = Breaker();
        var failing = new CountingProvider((_, _) => Task.FromResult(Result.Failure<AiAnalysisOutput>(AiAnalysisErrors.NetworkFailure())));
        for (var index = 0; index < 3; index++)
        {
            await Stage(gate, failing, breaker).AnalyzeAsync(Input, [], CancellationToken.None);
        }

        _clock.Advance(TimeSpan.FromSeconds(30));
        var probe = await Stage(gate, failing, breaker).AnalyzeAsync(Input, [], CancellationToken.None);

        AssertHeldForReview(probe, AiAnalysisStatus.NetworkFailure);
        Assert.Equal(AiCircuitState.Open, breaker.State);
        Assert.Equal(4, failing.Calls);
    }

    [Fact]
    public async Task AnalyzeAsync_DeterministicBlock_SkipsCapacityCircuitAndProvider_EvenWithTheCircuitOpen()
    {
        var gate = Gate();
        var breaker = Breaker();
        var failing = new CountingProvider((_, _) => Task.FromResult(Result.Failure<AiAnalysisOutput>(AiAnalysisErrors.Unavailable())));
        for (var index = 0; index < 3; index++)
        {
            await Stage(gate, failing, breaker).AnalyzeAsync(Input, [], CancellationToken.None);
        }

        var outcome = await Stage(gate, failing, breaker).AnalyzeAsync(Input, [DeterministicHigh], CancellationToken.None);

        Assert.Equal(AiAnalysisStatus.NotNeeded, outcome.Summary.Status);
        Assert.Empty(outcome.Findings);
        Assert.Equal(3, failing.Calls);
    }

    // ── Milestone 6 step 3: audit of the Block bypass and the open circuit ──────────────────────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_DeterministicBlock_UsesNoDisclosureEstimateCircuitRequestsTokensConcurrencyOrProvider()
    {
        using var admissions = _meters.Record(InMemoryAiCapacityGate.AdmissionsInstrument, InMemoryAiCapacityGate.ResultTag);
        using var reserved = _meters.Record(InMemoryAiCapacityGate.ReservedInputTokensInstrument, "none");
        var gate = Gate();
        var breaker = new CountingBreaker(Breaker());
        var disclosure = new CountingDisclosure();
        var provider = new CountingProvider((_, _) => Task.FromResult(Result.Success(new AiAnalysisOutput([])))) { Estimate = 20_000 };

        for (var index = 0; index < 25; index++)
        {
            var outcome = await Stage(gate, provider, breaker, disclosure).AnalyzeAsync(Input, [DeterministicHigh], CancellationToken.None);
            Assert.Equal(AiAnalysisStatus.NotNeeded, outcome.Summary.Status);
            Assert.Empty(outcome.Findings);
            Assert.Equal(0, gate.InFlight);
        }

        Assert.Equal((0, 0, 0, 0), (disclosure.Calls, provider.EstimateCalls, breaker.Acquired, provider.Calls));
        Assert.Equal(new Dictionary<string, int> { ["not_needed"] = 25 }, admissions.CountsByTag());
        Assert.Empty(reserved.CountsByTag());

        // The client's whole minute is intact: its maximum of 4 requests at 20,000 tokens each (exactly its 80,000-token
        // maximum) is admitted, and nothing more.
        for (var index = 0; index < 4; index++)
        {
            Assert.Equal(AiAnalysisStatus.Completed, (await Stage(gate, provider, breaker, disclosure).AnalyzeAsync(Input, [], CancellationToken.None)).Summary.Status);
        }

        AssertHeldForReview(await Stage(gate, provider, breaker, disclosure).AnalyzeAsync(Input, [], CancellationToken.None), AiAnalysisStatus.CapacityExceeded);
        Assert.Equal(4, provider.Calls);
    }

    [Fact]
    public async Task AnalyzeAsync_OpenCircuit_ConsumesNoRequestsTokensOrConcurrency_AndNoDecisionEndsBelowReview()
    {
        var gate = Gate();
        var breaker = Breaker();

        // Three failed calls of 10,000 tokens open the circuit: 3 of the client's 4 requests and 30,000 of its 80,000 tokens.
        var failing = new CountingProvider((_, _) => Task.FromResult(Result.Failure<AiAnalysisOutput>(AiAnalysisErrors.Unavailable()))) { Estimate = 10_000 };
        for (var index = 0; index < 3; index++)
        {
            await Stage(gate, failing, breaker).AnalyzeAsync(Input, [], CancellationToken.None);
        }

        Assert.Equal(AiCircuitState.Open, breaker.State);
        using var admissions = _meters.Record(InMemoryAiCapacityGate.AdmissionsInstrument, InMemoryAiCapacityGate.ResultTag);
        using var reserved = _meters.Record(InMemoryAiCapacityGate.ReservedInputTokensInstrument, "none");

        (ThreatFinding[] Deterministic, AiAnalysisStatus Status, SecurityDecision Decision)[] cases =
        [
            ([], AiAnalysisStatus.CircuitOpen, SecurityDecision.Review),
            ([DeterministicMedium], AiAnalysisStatus.CircuitOpen, SecurityDecision.Review),
            ([DeterministicHigh], AiAnalysisStatus.NotNeeded, SecurityDecision.Block),
        ];
        for (var round = 0; round < 10; round++)
        {
            foreach (var (deterministic, status, decision) in cases)
            {
                var outcome = await Stage(gate, failing, breaker).AnalyzeAsync(Input, deterministic, CancellationToken.None);

                Assert.Equal(status, outcome.Summary.Status);
                Assert.Equal(decision, FinalDecision([.. deterministic, .. outcome.Findings]));
                Assert.Equal(0, gate.InFlight);
            }
        }

        Assert.Equal(3, failing.Calls);
        Assert.Equal(new Dictionary<string, int> { ["not_needed"] = 10 }, admissions.CountsByTag());
        Assert.Empty(reserved.CountsByTag());

        // After the open period the probe gets exactly what the three failed calls left: 1 request and 50,000 tokens.
        _clock.Advance(TimeSpan.FromSeconds(30));
        var probe = new CountingProvider((_, _) => Task.FromResult(Result.Success(new AiAnalysisOutput([])))) { Estimate = 50_000 };
        Assert.Equal(AiAnalysisStatus.Completed, (await Stage(gate, probe, breaker).AnalyzeAsync(Input, [], CancellationToken.None)).Summary.Status);
        Assert.Equal(AiCircuitState.Closed, breaker.State);
        AssertHeldForReview(await Stage(gate, probe, breaker).AnalyzeAsync(Input, [], CancellationToken.None), AiAnalysisStatus.CapacityExceeded);
        Assert.Equal(1, probe.Calls);
    }

    [Fact]
    public async Task AnalyzeAsync_FailedProviderCalls_StillConsumeTheirRequestsAndTokens_ButReleaseConcurrency()
    {
        var gate = Gate();
        var failing = new CountingProvider((_, _) => Task.FromResult(Result.Failure<AiAnalysisOutput>(AiAnalysisErrors.RateLimited()))) { Estimate = 30_000 };
        var breaker = Breaker();

        await Stage(gate, failing, breaker).AnalyzeAsync(Input, [], CancellationToken.None);
        await Stage(gate, failing, breaker).AnalyzeAsync(Input, [], CancellationToken.None);
        var third = await Stage(gate, failing, breaker).AnalyzeAsync(Input, [], CancellationToken.None);

        // 2 × 30,000 were reserved and sent; a third 30,000 would exceed the client's 80,000 per minute.
        AssertHeldForReview(third, AiAnalysisStatus.CapacityExceeded);
        Assert.Equal(2, failing.Calls);
        Assert.Equal(0, gate.InFlight);
        Assert.Equal(AiCircuitState.Closed, breaker.State);
    }

    private static void AssertHeldForReview(AiAnalysisOutcome outcome, AiAnalysisStatus status)
    {
        Assert.Equal(status, outcome.Summary.Status);
        var finding = Assert.Single(outcome.Findings);
        Assert.Equal("InconclusiveAnalysis.AiAnalysisIncomplete", finding.Code);
        Assert.Equal(ThreatSeverity.Medium, finding.Severity);
    }

    private InMemoryAiCapacityGate Gate(Action<AiCapacityOptions>? configure = null)
    {
        var options = InMemoryAiCapacityGateTests.DefaultOptions();
        configure?.Invoke(options);
        return new InMemoryAiCapacityGate(
            Options.Create(options), new StaticClientDirectory(Client, "client-b"), _clock, _meters, new RecordingLogger<InMemoryAiCapacityGate>());
    }

    /// <summary>What the real risk and policy engines decide for these findings (deterministic and AI together).</summary>
    private static SecurityDecision FinalDecision(IReadOnlyList<ThreatFinding> findings) =>
        new RiskThresholdPolicyEngine().Decide(new SeverityRiskEngine().Assess(findings), findings).Decision;

    private AiAssistedAnalysis Stage(
        IAiCapacityGate gate, IAiSecurityAnalyzer provider, IAiCircuitBreaker? breaker = null, IAiDisclosurePolicy? disclosure = null) =>
        new(
            disclosure ?? new RedactingAiDisclosurePolicy(),
            new SeverityRiskEngine(),
            new RiskThresholdPolicyEngine(),
            gate,
            breaker ?? Breaker(),
            new Caller(),
            _clock,
            provider);

    /// <summary>The real breaker with the committed defaults (3 failures, 30 s open, 3 s probe).</summary>
    private InMemoryAiCircuitBreaker Breaker() => new(
        Options.Create(InMemoryAiCircuitBreakerTests.DefaultOptions()), _clock, _meters, new RecordingLogger<InMemoryAiCircuitBreaker>());

    private sealed class Caller : ICallerContext
    {
        public string ClientId => Client;
    }

    /// <summary>The real disclosure policy, counting how often the stage asks it.</summary>
    private sealed class CountingDisclosure : IAiDisclosurePolicy
    {
        private readonly RedactingAiDisclosurePolicy _inner = new();

        public int Calls { get; private set; }

        public AiDisclosure Prepare(NormalizedInput input)
        {
            Calls++;
            return _inner.Prepare(input);
        }
    }

    /// <summary>The real breaker, counting how often the stage asks it for a permit.</summary>
    private sealed class CountingBreaker(IAiCircuitBreaker inner) : IAiCircuitBreaker
    {
        public int Acquired { get; private set; }

        public AiCircuitPermit TryAcquire()
        {
            Acquired++;
            return inner.TryAcquire();
        }
    }

    private sealed class CountingProvider(Func<AiAnalysisRequest, CancellationToken, Task<Result<AiAnalysisOutput>>> respond) : IAiSecurityAnalyzer
    {
        private int _calls;
        private int _estimateCalls;

        public int Calls => Volatile.Read(ref _calls);

        public int EstimateCalls => Volatile.Read(ref _estimateCalls);

        public string Provider => "AnyProvider";

        public string Model => "any-model";

        public long Estimate { get; init; } = 500;

        public long EstimateInputTokens(AiAnalysisRequest request)
        {
            Interlocked.Increment(ref _estimateCalls);
            return Estimate;
        }

        public Task<Result<AiAnalysisOutput>> AnalyzeAsync(AiAnalysisRequest request, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            return respond(request, cancellationToken);
        }
    }
}
