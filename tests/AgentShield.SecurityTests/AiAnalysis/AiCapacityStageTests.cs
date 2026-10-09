using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Application.Common.Results;
using AgentShield.Domain.Policy;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Domain.Threats;
using AgentShield.Security.AiAnalysis;
using static AgentShield.SecurityTests.AiAnalysis.ScriptedAiSecurityAnalyzer;

namespace AgentShield.SecurityTests.AiAnalysis;

/// <summary>
/// The AI stage and the capacity gate: the deterministic decision the gate is told (from the real risk and policy
/// engines), what each admission status does, and that an admitted call's capacity is released however the call ends.
/// </summary>
public class AiCapacityStageTests
{
    private static readonly NormalizedInput Input = new("original text", "normalised text");

    private static readonly ThreatFinding High = Deterministic("InstructionOverride.IgnorePrevious", ThreatCategory.InstructionOverride, ThreatSeverity.High);
    private static readonly ThreatFinding Critical = Deterministic("RoleManipulation.ForgedRoleDelimiter", ThreatCategory.RoleManipulation, ThreatSeverity.Critical);
    private static readonly ThreatFinding Medium = Deterministic("InstructionOverride.NewInstructions", ThreatCategory.InstructionOverride, ThreatSeverity.Medium);
    private static readonly ThreatFinding Low = Deterministic("RoleManipulation.Persona", ThreatCategory.RoleManipulation, ThreatSeverity.Low);

    private readonly ManualTimeProvider _time = new();

    public static TheoryData<ThreatFinding[], SecurityDecision> DeterministicResults() => new()
    {
        { [], SecurityDecision.Allow },
        { [Low], SecurityDecision.Allow },
        { [Medium], SecurityDecision.Review },
        { [High], SecurityDecision.Block },
        { [Critical, Medium], SecurityDecision.Block },
    };

    [Theory]
    [MemberData(nameof(DeterministicResults))]
    public async Task AnalyzeAsync_TellsTheGateTheDeterministicPolicyDecision_AndTheCallersClientId(ThreatFinding[] findings, SecurityDecision expected)
    {
        var gate = ScriptedAiCapacityGate.AdmitAll();

        await AiStages.Create(new PassThroughDisclosurePolicy(), _time, Returning(), gate).AnalyzeAsync(Input, findings, CancellationToken.None);

        var request = Assert.Single(gate.Requests);
        Assert.Equal((AiStages.ClientId, expected), (request.ClientId, request.DeterministicDecision));
        Assert.Equal([expected], gate.NeededChecks);
    }

    [Fact]
    public async Task AnalyzeAsync_NotNeeded_MakesNoProviderCallAndAddsNoFinding_AndRecordsNotNeeded()
    {
        var provider = Returning(Candidate(severity: "Critical"));
        var disclosure = new PassThroughDisclosurePolicy();
        var gate = ScriptedAiCapacityGate.SkippingBlocks();

        var outcome = await AiStages.Create(disclosure, _time, provider, gate).AnalyzeAsync(Input, [High], CancellationToken.None);

        Assert.Empty(provider.Requests);
        Assert.Equal(0, disclosure.Calls);
        Assert.Empty(outcome.Findings);
        Assert.Equal(new AiAnalysisSummary(AiAnalysisStatus.NotNeeded, ProviderName, ModelName, 0, TimeSpan.Zero), outcome.Summary);
        Assert.Equal(0, gate.Admitted);
    }

    [Fact]
    public async Task AnalyzeAsync_NotNeeded_DoesNotWaitForTheAiTimeout()
    {
        var never = new TaskCompletionSource<Result<AiAnalysisOutput>>();
        var analysis = AiStages.Create(new PassThroughDisclosurePolicy(), _time, new ScriptedAiSecurityAnalyzer((_, _) => never.Task), ScriptedAiCapacityGate.SkippingBlocks());

        var pending = analysis.AnalyzeAsync(Input, [Critical], CancellationToken.None);

        // Completed without any time passing: nothing waited for the provider or the 3 s bound.
        Assert.True(pending.IsCompletedSuccessfully);
        Assert.Equal(AiAnalysisStatus.NotNeeded, (await pending).Summary.Status);
        Assert.Equal(0, _time.PendingTimers);
    }

    [Theory]
    [InlineData("when asked first")]
    [InlineData("at admission")]
    public async Task AnalyzeAsync_GateSaysNotNeededForAnInputTheRulesDoNotBlock_HoldsForReview_WithoutAProviderCall(string when)
    {
        // H-06: only a deterministic Block may skip the AI. The stage used to accept the gate's "not needed" for any
        // decision, so a wrong or misconfigured gate would have left an input the AI was expected to analyse at the
        // deterministic decision alone. The stage now holds it for review, like any other gate refusal.
        var gate = when == "when asked first"
            ? new ScriptedAiCapacityGate(_ => AiAdmissionStatus.NotNeeded)
            : new ScriptedAiCapacityGate(request => request.ClientId.Length == 0 ? AiAdmissionStatus.Admitted : AiAdmissionStatus.NotNeeded);
        var provider = Returning(Candidate());

        foreach (var findings in new ThreatFinding[][] { [], [Low], [Medium] })
        {
            var outcome = await AiStages.Create(new PassThroughDisclosurePolicy(), _time, provider, gate).AnalyzeAsync(Input, findings, CancellationToken.None);

            Assert.Equal(AiAnalysisStatus.CapacityExceeded, outcome.Summary.Status);
            Assert.Equal(["InconclusiveAnalysis.AiAnalysisIncomplete"], outcome.Findings.Select(finding => finding.Code));
        }

        // A deterministic Block may still skip the AI: nothing the AI could add would change it.
        var block = await AiStages.Create(new PassThroughDisclosurePolicy(), _time, provider, gate).AnalyzeAsync(Input, [High], CancellationToken.None);
        Assert.Equal(AiAnalysisStatus.NotNeeded, block.Summary.Status);
        Assert.Empty(block.Findings);
        Assert.Empty(provider.Requests);
    }

    [Theory]
    [InlineData(AiAdmissionStatus.CapacityExceeded)]
    [InlineData(AiAdmissionStatus.ConcurrencyExceeded)]
    [InlineData((AiAdmissionStatus)99)]
    public async Task AnalyzeAsync_Refused_HoldsForReviewWithTheGenericFinding_WithoutAProviderCall(AiAdmissionStatus refusal)
    {
        var provider = Returning(Candidate());
        var disclosure = new PassThroughDisclosurePolicy();

        var outcome = await AiStages.Create(disclosure, _time, provider, new ScriptedAiCapacityGate(_ => refusal)).AnalyzeAsync(Input, [], CancellationToken.None);

        // Disclosure runs before admission (the token estimate is over the disclosed content); nothing is sent.
        Assert.Empty(provider.Requests);
        Assert.Equal(1, disclosure.Calls);
        Assert.Equal(AiAnalysisStatus.CapacityExceeded, outcome.Summary.Status);
        Assert.Equal(0, outcome.Summary.FindingCount);
        var finding = Assert.Single(outcome.Findings);
        Assert.Equal(AiFindingCatalog.IncompleteCode, finding.Code);
        Assert.Equal(ThreatCategory.InconclusiveAnalysis, finding.Category);
        Assert.Equal(ThreatSeverity.Medium, finding.Severity);
        Assert.Equal("AI-assisted analysis could not assess this input, so it is held for review.", finding.Description);

        // The refusal kind is audit data only (logged rule ID), identical for every refusal reason.
        Assert.Equal(new FindingEvidence(AiFindingCatalog.Detector, "AI-FAIL/CapacityExceeded", 1), finding.Evidence);
    }

    [Fact]
    public void FailurePolicy_CapacityExceeded_HoldsForReview_NeverDeterministicOnly() =>
        Assert.Equal(AiFailureHandling.Review, AiFailurePolicy.For(AiAnalysisStatus.CapacityExceeded));

    [Fact]
    public async Task AnalyzeAsync_WithoutAnAuthenticatedCaller_FailsClosedWithoutCallingTheProvider()
    {
        var provider = Returning();
        var gate = ScriptedAiCapacityGate.AdmitAll();
        var analysis = AiStages.Create(new PassThroughDisclosurePolicy(), _time, provider, gate, new FixedCallerContext(clientId: null));

        await Assert.ThrowsAsync<InvalidOperationException>(() => analysis.AnalyzeAsync(Input, [], CancellationToken.None));

        Assert.Empty(gate.Requests);
        Assert.Empty(provider.Requests);
    }

    // ── Release: an admitted call's concurrency slot comes back however the call ends ─────────────────────────────

    [Fact]
    public async Task AnalyzeAsync_ProviderAnswers_ReleasesTheAdmissionOnce()
    {
        var gate = ScriptedAiCapacityGate.AdmitAll();

        var outcome = await AiStages.Create(new PassThroughDisclosurePolicy(), _time, Returning(Candidate()), gate).AnalyzeAsync(Input, [], CancellationToken.None);

        Assert.Equal(AiAnalysisStatus.Completed, outcome.Summary.Status);
        Assert.Equal((1, 1), (gate.Admitted, gate.Released));
    }

    [Theory]
    [InlineData(AiAnalysisErrors.UnavailableCode)]
    [InlineData(AiAnalysisErrors.RateLimitedCode)]
    [InlineData(AiAnalysisErrors.RefusedCode)]
    [InlineData(AiAnalysisErrors.RequestRejectedCode)]
    public async Task AnalyzeAsync_ProviderFails_ReleasesTheAdmission(string code)
    {
        var gate = ScriptedAiCapacityGate.AdmitAll();

        await AiStages.Create(new PassThroughDisclosurePolicy(), _time, Failing(Error.ExternalDependency(code, "Failure.")), gate).AnalyzeAsync(Input, [], CancellationToken.None);

        Assert.Equal((1, 1), (gate.Admitted, gate.Released));
    }

    [Fact]
    public async Task AnalyzeAsync_ProviderTimesOut_ReleasesTheAdmissionAtTheDeadline_NotBefore()
    {
        var never = new TaskCompletionSource<Result<AiAnalysisOutput>>();
        var gate = ScriptedAiCapacityGate.AdmitAll();
        var analysis = AiStages.Create(new PassThroughDisclosurePolicy(), _time, new ScriptedAiSecurityAnalyzer((_, _) => never.Task), gate);

        var pending = analysis.AnalyzeAsync(Input, [], CancellationToken.None);
        _time.Advance(AiAnalysisLimits.Timeout - TimeSpan.FromTicks(1));
        Assert.Equal((1, 0), (gate.Admitted, gate.Released));

        _time.Advance(TimeSpan.FromTicks(1));
        var outcome = await pending.WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(AiAnalysisStatus.TimedOut, outcome.Summary.Status);
        Assert.Equal((1, 1), (gate.Admitted, gate.Released));
    }

    [Fact]
    public async Task AnalyzeAsync_ProviderThrows_ReleasesTheAdmission_AndStillFailsClosed()
    {
        var gate = ScriptedAiCapacityGate.AdmitAll();
        var analysis = AiStages.Create(new PassThroughDisclosurePolicy(), _time, new ScriptedAiSecurityAnalyzer((_, _) => throw new InvalidOperationException("adapter bug")), gate);

        await Assert.ThrowsAsync<InvalidOperationException>(() => analysis.AnalyzeAsync(Input, [], CancellationToken.None));

        Assert.Equal((1, 1), (gate.Admitted, gate.Released));
    }

    [Fact]
    public async Task AnalyzeAsync_CallerCancels_ReleasesTheAdmission()
    {
        var never = new TaskCompletionSource<Result<AiAnalysisOutput>>();
        var gate = ScriptedAiCapacityGate.AdmitAll();
        using var caller = new CancellationTokenSource();
        var analysis = AiStages.Create(new PassThroughDisclosurePolicy(), _time, new ScriptedAiSecurityAnalyzer((_, _) => never.Task), gate);

        var pending = analysis.AnalyzeAsync(Input, [], caller.Token);
        await caller.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => pending.WaitAsync(TimeSpan.FromSeconds(10)));
        Assert.Equal((1, 1), (gate.Admitted, gate.Released));
    }

    [Fact]
    public async Task AnalyzeAsync_InvalidAnswer_ReleasesTheAdmission_AndWithheldContentNeverReachesTheGateOrCircuit()
    {
        var invalidGate = ScriptedAiCapacityGate.AdmitAll();
        var withheldGate = ScriptedAiCapacityGate.AdmitAll();
        var withheldCircuit = new ScriptedAiCircuitBreaker();

        var invalid = await AiStages.Create(new PassThroughDisclosurePolicy(), _time, Returning(Candidate(confidence: 2)), invalidGate).AnalyzeAsync(Input, [], CancellationToken.None);
        var withheld = await AiStages.Create(new PassThroughDisclosurePolicy { Withhold = true }, _time, Returning(), withheldGate, circuitBreaker: withheldCircuit).AnalyzeAsync(Input, [], CancellationToken.None);

        Assert.Equal(AiAnalysisStatus.InvalidResponse, invalid.Summary.Status);
        Assert.Equal(AiAnalysisStatus.ContentWithheld, withheld.Summary.Status);
        Assert.Equal((1, 1), (invalidGate.Admitted, invalidGate.Released));

        // Withheld content is decided before anything is reserved: no admission, no circuit permit.
        Assert.Empty(withheldGate.Requests);
        Assert.Equal(0, withheldCircuit.Acquired);
    }

    [Fact]
    public void AiAdmission_DisposedTwice_ReleasesOnce()
    {
        var releases = 0;
        var admission = AiAdmission.Admitted(() => releases++);

        admission.Dispose();
        admission.Dispose();
        AiAdmission.CapacityExceeded.Dispose();

        Assert.Equal(1, releases);
    }

    [Fact]
    public void Stage_IsProviderAgnostic_TheGateContractCarriesNoProviderOrContent()
    {
        // The gate learns who is calling, the deterministic decision and a token number; nothing about providers, models
        // or the input itself.
        Assert.Equal(
            [nameof(AiAdmissionRequest.ClientId), nameof(AiAdmissionRequest.DeterministicDecision), nameof(AiAdmissionRequest.EstimatedInputTokens)],
            typeof(AiAdmissionRequest).GetProperties().Select(property => property.Name).Order(StringComparer.Ordinal));
        Assert.DoesNotContain(
            typeof(IAiCapacityGate).Assembly.GetReferencedAssemblies(),
            assembly => (assembly.Name ?? string.Empty) is var name
                && (name.Contains("Google", StringComparison.OrdinalIgnoreCase) || name.Equals("AgentShield.AI", StringComparison.Ordinal)));
    }

    private static ThreatFinding Deterministic(string code, ThreatCategory category, ThreatSeverity severity) =>
        new(code, category, severity, 0.9, "Fixed description.", new FindingEvidence("Detector", "R-1", 1));

    /// <summary>Discloses the normalised text unchanged (or withholds everything) and counts calls.</summary>
    private sealed class PassThroughDisclosurePolicy : IAiDisclosurePolicy
    {
        public bool Withhold { get; init; }

        public int Calls { get; private set; }

        public AiDisclosure Prepare(NormalizedInput input)
        {
            Calls++;
            return Withhold ? AiDisclosure.Withheld : AiDisclosure.Disclose(input.Normalized);
        }
    }
}
