using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Abstractions.Context;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Application.Firewall.AnalyzeInput;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Domain.Threats;
using AgentShield.Security.Aggregation;

namespace AgentShield.UnitTests.Application.Firewall;

public class AnalyzeInputUseCaseTests
{
    private readonly ManualTimeProvider _time = new();
    private readonly StubNormalizer _normalizer = new();
    private readonly RecordingRiskEngine _risk = new(new RiskAssessment(75));
    private readonly RecordingPolicyEngine _policy = new(new PolicyDecision(SecurityDecision.Block, "Policy.Test", "Blocked for test."));
    private readonly RecordingSink _sink = new();
    private readonly List<ISecurityEventSink> _otherSinks = [];
    private readonly StubAiAnalysis _ai = new();

    [Fact]
    public async Task ExecuteAsync_RunsEveryDetectorOnTheNormalisedInput()
    {
        var first = new StubDetector();
        var second = new StubDetector();
        var third = new StubDetector();

        await CreateUseCase(first, second, third).ExecuteAsync(new AnalyzeInputRequest("raw input"), CancellationToken.None);

        Assert.All([first, second, third], detector =>
        {
            var received = Assert.Single(detector.Received);
            Assert.Equal("raw input", received.Original);
            Assert.Equal(StubNormalizer.Prefix + "raw input", received.Normalized);
        });
    }

    [Fact]
    public async Task ExecuteAsync_CollectsFindingsFromAllDetectors_MostSevereFirstThenByCode()
    {
        var lowAndCritical = new StubDetector(Finding("Z.Low", ThreatSeverity.Low), Finding("B.Critical", ThreatSeverity.Critical));
        var nothing = new StubDetector();
        var twoHigh = new StubDetector(Finding("Y.High", ThreatSeverity.High), Finding("A.High", ThreatSeverity.High));

        var result = await CreateUseCase(lowAndCritical, nothing, twoHigh).ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None);

        string[] expected = ["B.Critical", "A.High", "Y.High", "Z.Low"];
        Assert.Equal(expected, result.Value.Findings.Select(finding => finding.Code));
        Assert.Equal(expected, _risk.Received.Select(finding => finding.Code));
        Assert.Equal(expected, _policy.ReceivedFindings.Select(finding => finding.Code));
    }

    [Fact]
    public async Task ExecuteAsync_DetectorOrderDoesNotChangeTheResponse()
    {
        StubDetector[] detectors = [new(Finding("A.One", ThreatSeverity.Medium)), new(Finding("B.Two", ThreatSeverity.Medium))];

        var forward = await CreateUseCase(detectors).ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None);
        var reversed = await CreateUseCase([.. detectors.Reverse()]).ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None);

        Assert.Equal(forward.Value.Findings, reversed.Value.Findings);
    }

    [Fact]
    public async Task ExecuteAsync_DuplicateFindingsFromTwoDetectors_AreFusedBeforeRiskPolicyAndAudit()
    {
        var fromFirst = new ThreatFinding("A.Same", ThreatCategory.InstructionOverride, ThreatSeverity.Medium, 0.6, "Test finding.", new FindingEvidence("First", "F-1", 1));
        var fromSecond = new ThreatFinding("A.Same", ThreatCategory.InstructionOverride, ThreatSeverity.High, 0.5, "Test finding.", new FindingEvidence("Second", "S-1", 2));

        var result = await CreateUseCase(new StubDetector(fromFirst), new StubDetector(fromSecond))
            .ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None);

        var fused = Assert.Single(_risk.Received);
        Assert.Equal(ThreatSeverity.High, fused.Severity);
        Assert.Equal(0.6, fused.Confidence);
        Assert.Equal(["S-1", "F-1"], fused.AllEvidence.Select(evidence => evidence.RuleId));
        Assert.Single(_policy.ReceivedFindings);
        Assert.Single(Assert.Single(_sink.Events).Findings);
        Assert.Equal(new FindingResponse("A.Same", ThreatCategory.InstructionOverride, ThreatSeverity.High, 0.6, "Test finding."), Assert.Single(result.Value.Findings));
    }

    [Fact]
    public async Task ExecuteAsync_PolicyDecidesFromTheRiskAssessment_AndBlockIsASuccessfulResult()
    {
        var result = await CreateUseCase(new StubDetector(Finding("A.High", ThreatSeverity.High)))
            .ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Same(_risk.Result, _policy.ReceivedRisk);
        Assert.Equal(SecurityDecision.Block, result.Value.Decision);
        Assert.Equal("Blocked for test.", result.Value.Reason);
        Assert.Equal(new RiskResponse(RiskLevel.High, 75), result.Value.Risk);
    }

    [Fact]
    public async Task ExecuteAsync_ResponseFindings_CarryClientFieldsOfTheFinding()
    {
        var finding = new ThreatFinding("A.Code", ThreatCategory.SecretExtraction, ThreatSeverity.High, 0.8, "Desc.", new FindingEvidence("R-9", 3));

        var result = await CreateUseCase(new StubDetector(finding)).ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None);

        Assert.Equal(
            new FindingResponse("A.Code", ThreatCategory.SecretExtraction, ThreatSeverity.High, 0.8, "Desc."),
            Assert.Single(result.Value.Findings));
    }

    [Fact]
    public async Task ExecuteAsync_PublishesOneSecurityEventMatchingTheResponse()
    {
        var finding = Finding("A.High", ThreatSeverity.High);
        var slowDetector = new StubDetector(finding) { OnDetect = () => _time.Advance(TimeSpan.FromMilliseconds(25)) };

        var result = await CreateUseCase(slowDetector).ExecuteAsync(new AnalyzeInputRequest("twelve chars"), CancellationToken.None);

        var securityEvent = Assert.Single(_sink.Events);
        Assert.Equal(result.Value.SecurityEventId, securityEvent.Id.Value);
        Assert.Equal(7, securityEvent.Id.Value.Version);
        Assert.Equal("corr-123", securityEvent.CorrelationId);
        Assert.Equal(_time.GetUtcNow(), securityEvent.OccurredAt);
        Assert.Same(_policy.Result, securityEvent.Decision);
        Assert.Same(_risk.Result, securityEvent.Risk);
        Assert.Equal([finding], securityEvent.Findings);
        Assert.Equal(12, securityEvent.InputLength);
        Assert.Equal(TimeSpan.FromMilliseconds(25), securityEvent.Duration);
        Assert.Equal(25.0, result.Value.DurationMs);
    }

    [Fact]
    public async Task ExecuteAsync_EachAnalysisGetsANewSecurityEventId()
    {
        var useCase = CreateUseCase(new StubDetector());

        var first = await useCase.ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None);
        var second = await useCase.ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None);

        Assert.NotEqual(first.Value.SecurityEventId, second.Value.SecurityEventId);
    }

    [Fact]
    public async Task ExecuteAsync_DetectorThrows_PropagatesAndRecordsNoDecision()
    {
        var failing = new StubDetector { OnDetect = () => throw new InvalidOperationException("detector bug") };

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            CreateUseCase(new StubDetector(), failing).ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None));

        Assert.Null(_policy.ReceivedRisk);
        Assert.Empty(_sink.Events);
    }

    [Fact]
    public async Task ExecuteAsync_Cancelled_StopsBeforeDecidingOrAuditing()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();
        var detector = new StubDetector();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CreateUseCase(detector).ExecuteAsync(new AnalyzeInputRequest("x"), cancellation.Token));

        Assert.Empty(detector.Received);
        Assert.Empty(_sink.Events);
    }

    [Fact]
    public async Task ExecuteAsync_AiDisabled_DecidesOnDetectorFindingsAlone_AndRecordsAiAsDisabled()
    {
        var finding = Finding("A.High", ThreatSeverity.High);

        var result = await CreateUseCase(new StubDetector(finding)).ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None);

        Assert.Equal([finding], _risk.Received);
        Assert.Equal(["A.High"], result.Value.Findings.Select(response => response.Code));
        Assert.Same(AiAnalysisSummary.Disabled, Assert.Single(_sink.Events).AiAnalysis);
    }

    [Fact]
    public async Task ExecuteAsync_AiStage_ReceivesTheNormalisedInputAndTheFusedDetectorFindings()
    {
        var first = new ThreatFinding("A.Same", ThreatCategory.InstructionOverride, ThreatSeverity.Medium, 0.6, "Test finding.", new FindingEvidence("First", "F-1", 1));
        var second = first with { };
        var other = Finding("B.Other", ThreatSeverity.Critical);

        await CreateUseCase(new StubDetector(first), new StubDetector(second, other)).ExecuteAsync(new AnalyzeInputRequest("raw"), CancellationToken.None);

        var call = Assert.Single(_ai.Calls);
        Assert.Equal(StubNormalizer.Prefix + "raw", call.Input.Normalized);
        Assert.Equal(["B.Other", "A.Same"], call.DeterministicFindings.Select(finding => finding.Code));
    }

    [Fact]
    public async Task ExecuteAsync_AiFindings_AreFusedWithDetectorFindingsBeforeRiskPolicyAuditAndResponse()
    {
        var detector = new ThreatFinding("A.Same", ThreatCategory.InstructionOverride, ThreatSeverity.Medium, 0.6, "Detector text.", new FindingEvidence("Det", "D-1", 1));
        _ai.Outcome = Completed(
            new ThreatFinding("A.Same", ThreatCategory.InstructionOverride, ThreatSeverity.Low, 0.9, "AI text.", new FindingEvidence("AiAnalysis", "AI/Stub", 1)),
            new ThreatFinding("C.Ai", ThreatCategory.SecretExtraction, ThreatSeverity.High, 0.7, "AI text.", new FindingEvidence("AiAnalysis", "AI/Stub", 1)));

        var result = await CreateUseCase(new StubDetector(detector)).ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None);

        string[] expected = ["C.Ai", "A.Same"];
        Assert.Equal(expected, _risk.Received.Select(finding => finding.Code));
        Assert.Equal(expected, _policy.ReceivedFindings.Select(finding => finding.Code));
        Assert.Equal(expected, Assert.Single(_sink.Events).Findings.Select(finding => finding.Code));
        Assert.Equal(expected, result.Value.Findings.Select(finding => finding.Code));

        // The one aggregator applies the usual rule (highest severity keeps its description and primary evidence).
        var fused = _risk.Received[1];
        Assert.Equal((ThreatSeverity.Medium, "Detector text."), (fused.Severity, fused.Description));
        Assert.Equal(["D-1", "AI/Stub"], fused.AllEvidence.Select(evidence => evidence.RuleId));
    }

    [Fact]
    public async Task ExecuteAsync_AiSummary_IsRecordedOnTheSecurityEvent()
    {
        var summary = new AiAnalysisSummary(AiAnalysisStatus.TimedOut, "Stub", "stub-model", 0, TimeSpan.FromSeconds(3));
        _ai.Outcome = new AiAnalysisOutcome(summary, []);

        await CreateUseCase(new StubDetector()).ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None);

        Assert.Same(summary, Assert.Single(_sink.Events).AiAnalysis);
    }

    [Fact]
    public async Task ExecuteAsync_AiStageTime_IsPartOfTheAnalysisDuration()
    {
        _ai.OnAnalyze = () => _time.Advance(TimeSpan.FromMilliseconds(400));

        var result = await CreateUseCase(new StubDetector()).ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None);

        Assert.Equal(400.0, result.Value.DurationMs);
    }

    [Fact]
    public async Task ExecuteAsync_AiStageThrows_PropagatesAndRecordsNoDecision()
    {
        _ai.OnAnalyze = () => throw new InvalidOperationException("stage bug");

        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            CreateUseCase(new StubDetector()).ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None));

        Assert.Null(_policy.ReceivedRisk);
        Assert.Empty(_sink.Events);
    }

    [Fact]
    public async Task ExecuteAsync_UnvalidatedNullInput_Throws()
    {
        await Assert.ThrowsAsync<ArgumentException>(() =>
            CreateUseCase().ExecuteAsync(new AnalyzeInputRequest(null), CancellationToken.None));
    }

    [Fact]
    public async Task ExecuteAsync_PublishesTheSameFinishedEventToEverySink_AfterThePolicyDecided()
    {
        var activity = new RecordingSink { OnPublish = _ => Assert.NotNull(_policy.ReceivedRisk) };
        _otherSinks.Add(activity);

        var result = await CreateUseCase(new StubDetector(Finding("A.High", ThreatSeverity.High)))
            .ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None);

        var logged = Assert.Single(_sink.Events);
        Assert.Same(logged, Assert.Single(activity.Events));
        Assert.Equal(result.Value.SecurityEventId, logged.Id.Value);
        Assert.Same(_policy.Result, logged.Decision);
    }

    [Fact]
    public async Task ExecuteAsync_ASinkFails_TheOtherSinksStillRecord_AndNoDecisionIsReturned()
    {
        // The activity history failing after a Block: the audit log still records the Block, and the caller gets the
        // failure instead of a decision, so a failing sink can never turn the Block into anything else, Allow included.
        var failure = new InvalidOperationException("activity store fault");
        var failing = new RecordingSink { OnPublish = _ => throw failure };
        var afterTheFailure = new RecordingSink();
        _otherSinks.AddRange([failing, afterTheFailure]);

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            CreateUseCase(new StubDetector(Finding("A.High", ThreatSeverity.High))).ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None));

        Assert.Same(failure, thrown);
        Assert.Equal(SecurityDecision.Block, Assert.Single(_sink.Events).Decision.Decision);
        Assert.Same(_sink.Events[0], Assert.Single(afterTheFailure.Events));
    }

    [Fact]
    public async Task ExecuteAsync_SeveralSinksFail_EveryFailureIsRaised()
    {
        _otherSinks.AddRange([
            new RecordingSink { OnPublish = _ => throw new InvalidOperationException("first") },
            new RecordingSink { OnPublish = _ => throw new TimeoutException("second") }]);

        var thrown = await Assert.ThrowsAsync<AggregateException>(() =>
            CreateUseCase(new StubDetector()).ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None));

        Assert.Equal([typeof(InvalidOperationException), typeof(TimeoutException)], thrown.InnerExceptions.Select(inner => inner.GetType()));
        Assert.Single(_sink.Events);
    }

    [Fact]
    public async Task ExecuteAsync_SinkCancelled_PropagatesTheCancellation()
    {
        _otherSinks.Add(new RecordingSink { OnPublish = _ => throw new OperationCanceledException() });

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            CreateUseCase(new StubDetector()).ExecuteAsync(new AnalyzeInputRequest("x"), CancellationToken.None));
    }

    private AnalyzeInputUseCase CreateUseCase(params IThreatDetector[] detectors) =>
        new(_normalizer, detectors, new FindingAggregator(), _ai, _risk, _policy, [_sink, .. _otherSinks], new FixedCorrelationContext("corr-123"), _time);

    private static ThreatFinding Finding(string code, ThreatSeverity severity) =>
        new(code, ThreatCategory.InstructionOverride, severity, 0.9, "Test finding.", new FindingEvidence("T-1", 1));

    private static AiAnalysisOutcome Completed(params ThreatFinding[] findings) =>
        new(new AiAnalysisSummary(AiAnalysisStatus.Completed, "Stub", "stub-model", findings.Length, TimeSpan.Zero), findings);

    private sealed class StubAiAnalysis : IAiAssistedAnalysis
    {
        public AiAnalysisOutcome Outcome { get; set; } = AiAnalysisOutcome.Disabled;

        public Action? OnAnalyze { get; set; }

        public List<(NormalizedInput Input, IReadOnlyList<ThreatFinding> DeterministicFindings)> Calls { get; } = [];

        public Task<AiAnalysisOutcome> AnalyzeAsync(NormalizedInput input, IReadOnlyList<ThreatFinding> deterministicFindings, CancellationToken cancellationToken)
        {
            Calls.Add((input, deterministicFindings));
            OnAnalyze?.Invoke();
            return Task.FromResult(Outcome);
        }
    }

    private sealed class StubNormalizer : IInputNormalizer
    {
        public const string Prefix = "normalised:";

        public NormalizedInput Normalize(string input) => new(input, Prefix + input);
    }

    private sealed class StubDetector(params ThreatFinding[] findings) : IThreatDetector
    {
        public List<NormalizedInput> Received { get; } = [];

        public Action? OnDetect { get; init; }

        public IReadOnlyList<ThreatFinding> Detect(NormalizedInput input)
        {
            Received.Add(input);
            OnDetect?.Invoke();
            return findings;
        }
    }

    private sealed class RecordingRiskEngine(RiskAssessment result) : IRiskEngine
    {
        public RiskAssessment Result { get; } = result;

        public IReadOnlyList<ThreatFinding> Received { get; private set; } = [];

        public RiskAssessment Assess(IReadOnlyList<ThreatFinding> findings)
        {
            Received = [.. findings];
            return Result;
        }
    }

    private sealed class RecordingPolicyEngine(PolicyDecision result) : IPolicyEngine
    {
        public PolicyDecision Result { get; } = result;

        public RiskAssessment? ReceivedRisk { get; private set; }

        public IReadOnlyList<ThreatFinding> ReceivedFindings { get; private set; } = [];

        public PolicyDecision Decide(RiskAssessment risk, IReadOnlyList<ThreatFinding> findings)
        {
            ReceivedRisk = risk;
            ReceivedFindings = [.. findings];
            return Result;
        }
    }

    private sealed class RecordingSink : ISecurityEventSink
    {
        public List<SecurityEvent> Events { get; } = [];

        /// <summary>Runs before the event is recorded; throwing makes the sink fail without recording it.</summary>
        public Action<SecurityEvent>? OnPublish { get; init; }

        public ValueTask PublishAsync(SecurityEvent securityEvent, CancellationToken cancellationToken)
        {
            OnPublish?.Invoke(securityEvent);
            Events.Add(securityEvent);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FixedCorrelationContext(string correlationId) : ICorrelationContext
    {
        public string CorrelationId { get; } = correlationId;
    }

    /// <summary>Time that moves only when told to, so durations are exact.</summary>
    private sealed class ManualTimeProvider : TimeProvider
    {
        private long _ticks;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => _ticks;

        public override DateTimeOffset GetUtcNow() => new DateTimeOffset(2026, 9, 29, 12, 0, 0, TimeSpan.Zero).AddTicks(_ticks);

        public void Advance(TimeSpan by) => _ticks += by.Ticks;
    }
}
