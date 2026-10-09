using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Application.Common.Results;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Domain.Threats;
using AgentShield.Security.AiAnalysis;
using static AgentShield.SecurityTests.AiAnalysis.ScriptedAiSecurityAnalyzer;

namespace AgentShield.SecurityTests.AiAnalysis;

/// <summary>
/// The AI stage and the circuit breaker (Milestone 6 step 2): the order Block skip → disclosure → circuit → capacity →
/// one provider call, what an open circuit does, what the circuit is told, and the input-token reservation it passes on.
/// The real breaker's state machine is tested in UnitTests.
/// </summary>
public class AiCircuitStageTests
{
    private static readonly NormalizedInput Input = new("original text", "normalised text");

    private static readonly ThreatFinding High = new(
        "InstructionOverride.IgnorePrevious", ThreatCategory.InstructionOverride, ThreatSeverity.High, 0.9,
        "Fixed description.", new FindingEvidence("InstructionOverride", "IO-001", 1));

    private readonly ManualTimeProvider _time = new();

    [Fact]
    public async Task AnalyzeAsync_CircuitOpen_HoldsForReview_WithoutAProviderCall_AndWithoutAskingForCapacity()
    {
        var provider = Returning(Candidate(severity: "Critical"));
        var gate = ScriptedAiCapacityGate.AdmitAll();
        var circuit = new ScriptedAiCircuitBreaker { IsOpen = true };

        var outcome = await AiStages.Create(new CountingDisclosure(), _time, provider, gate, circuitBreaker: circuit).AnalyzeAsync(Input, [], CancellationToken.None);

        Assert.Empty(provider.Requests);
        Assert.Empty(gate.Requests);
        Assert.Equal(AiAnalysisStatus.CircuitOpen, outcome.Summary.Status);
        var finding = Assert.Single(outcome.Findings);
        Assert.Equal(AiFindingCatalog.IncompleteCode, finding.Code);
        Assert.Equal("AI-assisted analysis could not assess this input, so it is held for review.", finding.Description);
        Assert.Equal(new FindingEvidence(AiFindingCatalog.Detector, "AI-FAIL/CircuitOpen", 1), finding.Evidence);
    }

    [Fact]
    public async Task AnalyzeAsync_DeterministicBlock_NeverTouchesTheCircuitTheGateOrTheProvider()
    {
        var provider = Returning();
        var gate = ScriptedAiCapacityGate.SkippingBlocks();
        var circuit = new ScriptedAiCircuitBreaker { IsOpen = true };
        var disclosure = new CountingDisclosure();

        var outcome = await AiStages.Create(disclosure, _time, provider, gate, circuitBreaker: circuit).AnalyzeAsync(Input, [High], CancellationToken.None);

        Assert.Equal(AiAnalysisStatus.NotNeeded, outcome.Summary.Status);
        Assert.Empty(outcome.Findings);
        Assert.Equal(0, circuit.Acquired);
        Assert.Empty(gate.Requests);
        Assert.Empty(provider.Requests);
        Assert.Equal(0, disclosure.Calls);
    }

    public static TheoryData<string, AiAnalysisStatus> Outcomes() => new()
    {
        { "answer", AiAnalysisStatus.Completed },
        { "invalid", AiAnalysisStatus.Completed },
        { "malformed", AiAnalysisStatus.MalformedResponse },
        { "refused", AiAnalysisStatus.Refused },
        { "rejected", AiAnalysisStatus.UnclassifiedFailure },
        { "429", AiAnalysisStatus.RateLimited },
        { "503", AiAnalysisStatus.Unavailable },
        { "network", AiAnalysisStatus.NetworkFailure },
        { "provider-timeout", AiAnalysisStatus.TimedOut },
    };

    [Theory]
    [MemberData(nameof(Outcomes))]
    public async Task AnalyzeAsync_ReportsTheNormalisedOutcomeOfTheOneProviderCall_ToTheCircuit(string scenario, AiAnalysisStatus reported)
    {
        var provider = scenario switch
        {
            "answer" => Returning(Candidate()),
            "invalid" => Returning(Candidate(confidence: 2)),
            "malformed" => ReturningJson("ALLOW"),
            "refused" => Failing(AiAnalysisErrors.Refused()),
            "rejected" => Failing(AiAnalysisErrors.RequestRejected()),
            "429" => Failing(AiAnalysisErrors.RateLimited()),
            "503" => Failing(AiAnalysisErrors.Unavailable()),
            "network" => Failing(AiAnalysisErrors.NetworkFailure()),
            _ => Failing(AiAnalysisErrors.Timeout()),
        };
        var circuit = new ScriptedAiCircuitBreaker();

        await AiStages.Create(new CountingDisclosure(), _time, provider, circuitBreaker: circuit).AnalyzeAsync(Input, [], CancellationToken.None);

        // An invalid answer is still an answer: the provider is reachable, validation is not the circuit's business.
        Assert.Equal([reported], circuit.Reports);
        Assert.Single(provider.Requests);
    }

    [Theory]
    [InlineData("429")]
    [InlineData("503")]
    [InlineData("network")]
    public async Task AnalyzeAsync_ProviderAvailabilityFailure_IsNotRetried(string scenario)
    {
        var provider = Failing(scenario switch
        {
            "429" => AiAnalysisErrors.RateLimited(),
            "503" => AiAnalysisErrors.Unavailable(),
            _ => AiAnalysisErrors.NetworkFailure(),
        });

        var outcome = await AiStages.Create(new CountingDisclosure(), _time, provider).AnalyzeAsync(Input, [], CancellationToken.None);

        Assert.Single(provider.Requests);
        Assert.Equal(AiFindingCatalog.IncompleteCode, Assert.Single(outcome.Findings).Code);
    }

    [Fact]
    public async Task AnalyzeAsync_StageTimeout_IsReportedAsTimedOut()
    {
        var never = new TaskCompletionSource<Result<AiAnalysisOutput>>();
        var circuit = new ScriptedAiCircuitBreaker();
        var pending = AiStages.Create(new CountingDisclosure(), _time, new ScriptedAiSecurityAnalyzer((_, _) => never.Task), circuitBreaker: circuit)
            .AnalyzeAsync(Input, [], CancellationToken.None);

        _time.Advance(AiAnalysisLimits.Timeout);
        await pending.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal([AiAnalysisStatus.TimedOut], circuit.Reports);
    }

    [Fact]
    public async Task AnalyzeAsync_ProbePermit_BoundsTheCallByTheProbeTimeout()
    {
        var never = new TaskCompletionSource<Result<AiAnalysisOutput>>();
        var circuit = new ScriptedAiCircuitBreaker { ProbeTimeout = TimeSpan.FromSeconds(1) };
        var pending = AiStages.Create(new CountingDisclosure(), _time, new ScriptedAiSecurityAnalyzer((_, _) => never.Task), circuitBreaker: circuit)
            .AnalyzeAsync(Input, [], CancellationToken.None);

        _time.Advance(TimeSpan.FromSeconds(1) - TimeSpan.FromTicks(1));
        Assert.False(pending.IsCompleted);
        _time.Advance(TimeSpan.FromTicks(1));
        var outcome = await pending.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(AiAnalysisStatus.TimedOut, outcome.Summary.Status);
        Assert.Equal(TimeSpan.FromSeconds(1), outcome.Summary.Duration);
        Assert.Equal([AiAnalysisStatus.TimedOut], circuit.Reports);
    }

    [Theory]
    [InlineData(AiAdmissionStatus.CapacityExceeded)]
    [InlineData(AiAdmissionStatus.ConcurrencyExceeded)]
    public async Task AnalyzeAsync_CapacityRefusedAfterThePermit_ReleasesThePermitWithoutAnOutcome(AiAdmissionStatus refusal)
    {
        var circuit = new ScriptedAiCircuitBreaker { ProbeTimeout = TimeSpan.FromSeconds(3) };

        var outcome = await AiStages.Create(new CountingDisclosure(), _time, Returning(), ScriptedAiCapacityGate.Refusing(refusal), circuitBreaker: circuit)
            .AnalyzeAsync(Input, [], CancellationToken.None);

        // No call was made, so the circuit learns nothing and a probe slot is handed back rather than burnt.
        Assert.Equal(AiAnalysisStatus.CapacityExceeded, outcome.Summary.Status);
        Assert.Empty(circuit.Reports);
        Assert.Equal(1, circuit.Abandoned);
    }

    [Fact]
    public async Task AnalyzeAsync_ProviderThrows_ReleasesThePermitWithoutAnOutcome()
    {
        var circuit = new ScriptedAiCircuitBreaker();
        var analysis = AiStages.Create(new CountingDisclosure(), _time, new ScriptedAiSecurityAnalyzer((_, _) => throw new InvalidOperationException("bug")), circuitBreaker: circuit);

        await Assert.ThrowsAsync<InvalidOperationException>(() => analysis.AnalyzeAsync(Input, [], CancellationToken.None));

        Assert.Empty(circuit.Reports);
        Assert.Equal(1, circuit.Abandoned);
    }

    [Theory]
    [InlineData(0L, 15L)]
    [InlineData(-5L, 15L)]
    [InlineData(10L, 15L)]
    [InlineData(5_000L, 5_000L)]
    public async Task AnalyzeAsync_ReservesTheAdapterEstimate_NeverBelowTheByteFloor(long adapterEstimate, long reserved)
    {
        // Floor for "normalised text" (15 ASCII bytes) and no deterministic findings: 15.
        var provider = new ScriptedAiSecurityAnalyzer((_, _) => Task.FromResult(Result.Success(new AiAnalysisOutput([])))) { Estimate = _ => adapterEstimate };
        var gate = ScriptedAiCapacityGate.AdmitAll();

        await AiStages.Create(new CountingDisclosure(), _time, provider, gate).AnalyzeAsync(Input, [], CancellationToken.None);

        Assert.Equal(reserved, Assert.Single(gate.Requests).EstimatedInputTokens);
    }

    private sealed class CountingDisclosure : IAiDisclosurePolicy
    {
        public int Calls { get; private set; }

        public AiDisclosure Prepare(NormalizedInput input)
        {
            Calls++;
            return AiDisclosure.Disclose(input.Normalized);
        }
    }
}
