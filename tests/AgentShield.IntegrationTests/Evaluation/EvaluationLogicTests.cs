using System.Reflection;
using AgentShield.Evaluation;
using AgentShield.Evaluation.Dataset;
using AgentShield.Evaluation.Hosting;
using AgentShield.Evaluation.Report;
using AgentShield.Evaluation.Results;
using AgentShield.Evaluation.Run;
using AgentShield.Evaluation.Safety;

namespace AgentShield.IntegrationTests.Evaluation;

/// <summary>The evaluation runner's pure logic: safety limits, stop rules, planning, records, metrics and artifacts.</summary>
public class EvaluationLogicTests
{
    private static readonly Lazy<EvaluationDataset> Set = new(() => EvaluationDataset.Load(Path.Combine(AppContext.BaseDirectory, "Evaluation", "ai-security-evaluation-set.json")));

    // ── Safety limits and command line ──────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(90, 20, 15, 470, true)]
    [InlineData(90, 20, null, 470, false)] // provider RPM not stated
    [InlineData(90, 20, 15, null, false)] // requests left today not stated
    [InlineData(90, 14, 15, 470, false)] // faster than AgentShield's own 4 calls per minute
    [InlineData(90, 15, 6, 470, false)] // 4 per minute is more than half of 6 RPM
    [InlineData(240, 20, 15, 470, false)] // above half of the day's remaining requests and the ceiling
    [InlineData(151, 20, 15, 1000, false)] // above the per-session ceiling
    [InlineData(0, 20, 15, 470, false)]
    public void SafetyLimits_AllowOnlyARealRunFarBelowTheStatedProviderLimits(int maxCalls, int spacing, int? rpm, int? rpdRemaining, bool allowed) =>
        Assert.Equal(allowed, SafetyLimits.Check(maxCalls, spacing, rpm, rpdRemaining).Count == 0);

    [Fact]
    public void CommandLine_RealCommandsNeedACapAndTheProviderLimits_SimulationsNeverUseTheRealResults()
    {
        var results = Path.Combine(Path.GetTempPath(), "results");

        Assert.NotEmpty(CommandLine.Parse(["final"], results).Problems);
        Assert.NotEmpty(CommandLine.Parse(["plan", "--max-calls", "90"], results).Problems);
        Assert.Empty(CommandLine.Parse(["final", "--max-calls", "90", "--provider-rpm", "15", "--provider-rpd-remaining", "470"], results).Problems);
        Assert.NotEmpty(CommandLine.Parse(["simulate", "--max-calls", "90"], results).Problems);
        Assert.Empty(CommandLine.Parse(["simulate", "--max-calls", "90", "--results", Path.Combine(results, "sim")], results).Problems);
        Assert.NotEmpty(CommandLine.Parse(["final", "--max-calls", "90", "--provider-rpm", "15", "--provider-rpd-remaining", "470", "--subset", "2"], results).Problems);
        Assert.NotEmpty(CommandLine.Parse(["final", "--max-calls", "90", "--provider-rpm", "15", "--provider-rpd-remaining", "470", "--retry"], results).Problems);
        Assert.Equal(Subset.Benign, CommandLine.Parse(["report", "--subset", "benign"], results).Subset);
    }

    [Fact]
    public void CommandLine_RealRunsUseOnlyTheRealResults_SoCompletedFixturesAreNeverSentAgain()
    {
        var results = Path.Combine(Path.GetTempPath(), "results");
        var other = Path.Combine(Path.GetTempPath(), "other-results");
        string[] limits = ["--max-calls", "90", "--provider-rpm", "15", "--provider-rpd-remaining", "470"];

        // Regression: another directory starts from an empty store, so every fixture already completed in the real
        // results would be planned and sent to Gemini again.
        Assert.NotEmpty(CommandLine.Parse(["final", .. limits, "--results", other], results).Problems);
        Assert.NotEmpty(CommandLine.Parse(["plan", .. limits, "--results", other], results).Problems);
        Assert.Empty(CommandLine.Parse(["final", .. limits, "--results", results], results).Problems);
        Assert.Empty(CommandLine.Parse(["plan", .. limits], results).Problems);
    }

    [Fact]
    public void RealRun_OnlyWithTheRealProviderTheSystemClockAndTheCommittedConfiguration()
    {
        SessionOptions real = new() { Mode = RunMode.Real, MaxCalls = 90, SpacingSeconds = 20, ProviderRpm = 15, ProviderRpdRemaining = 470 };

        Assert.Empty(SessionRunner.Validate(real));
        Assert.NotEmpty(SessionRunner.Validate(real with { FakeTransport = (_, _, _) => throw new InvalidOperationException() }));
        Assert.NotEmpty(SessionRunner.Validate(real with { Settings = [new("Ai:TimeoutSeconds", "2")] }));
        Assert.NotEmpty(SessionRunner.Validate(real with { Clock = new VirtualClock() }));
        Assert.NotEmpty(SessionRunner.Validate(new SessionOptions { Mode = RunMode.Test, MaxCalls = 1 }));
    }

    [Fact]
    public void Observer_NeverTakesASlotBeyondTheCapOrWhileSendingIsNotAllowed()
    {
        var state = new ObserverState(2, TimeProvider.System, null);

        Assert.False(state.TryTakeSlot());
        state.SendAllowed = true;
        Assert.True(state.TryTakeSlot());
        Assert.True(state.TryTakeSlot());
        Assert.False(state.TryTakeSlot());
        Assert.Equal((2, 2), (state.InFlight, state.Refused));
    }

    // ── Stop rules ──────────────────────────────────────────────────────────────────────────────────────────────────

    public static TheoryData<string[], string?> StopSequences() => new()
    {
        { ["Completed", "Completed", "Completed"], null },
        { ["Completed", "429"], "HTTP 429 from Gemini (rate limited)" },
        { ["503", "Completed", "503"], "second HTTP 5xx / unavailable answer from Gemini" },
        { ["Completed", "TimedOut"], "AI analysis timed out" },
        { ["MalformedResponse", "InvalidResponse"], "two failed AI analyses in a row" },
        { ["503", "MalformedResponse"], "two failed AI analyses in a row" },
        { ["Completed", "slow-call"], "Gemini call at or above 2,500 ms" },
        { ["slow-stage"], null },
        { ["Completed", "slow-stage"], "AI stage at or above 2,700 ms" },
        { ["Completed", "circuit-open"], "circuit Open" },
    };

    [Theory]
    [MemberData(nameof(StopSequences))]
    public void StopRules_StopAtTheFirstUnsafeSignal(string[] sequence, string? expected)
    {
        var rules = new StopRules();
        string? reason = null;
        foreach (var step in sequence)
        {
            reason = rules.After(Attempt(step), refusedByObserver: 0);
            if (reason is not null)
            {
                break;
            }
        }

        Assert.Equal(expected, reason);
    }

    [Fact]
    public void StopRules_StopOnARefusedRequest_AnApiError_OrADeterministicBlockThatReachedTheProvider()
    {
        Assert.NotNull(new StopRules().After(Attempt("Completed"), refusedByObserver: 1));
        Assert.NotNull(new StopRules().After(Attempt("Completed") with { ApiStatus = 500 }, 0));
        Assert.NotNull(new StopRules().After(Attempt("NotNeeded") with { ProviderCallAllowed = false, ProviderCallCount = 1 }, 0));
        Assert.Null(new StopRules().After(Attempt("NotNeeded") with { ProviderCallAllowed = false, ProviderCallCount = 0, ProviderCall = null }, 0));
    }

    // ── Planning (resume) ───────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Planner_SkipsValidResults_AndOrdersDeterministicBlocksThenNewThenPreviouslyFailed()
    {
        var baseline = Set.Value.Fixtures.ToDictionary(f => f.Id, f => Baseline(f.Id, f.Id is "A01" or "B01" ? Labels.Block : Labels.Allow), StringComparer.Ordinal);
        AttemptRecord[] attempts =
        [
            Attempt("Completed") with { FixtureId = "C01", Sequence = 1 },
            Attempt("TimedOut") with { FixtureId = "C05", Sequence = 2 },
            Attempt("NotNeeded") with { FixtureId = "A01", Sequence = 3, ProviderCallAllowed = false },
            Attempt("Unavailable") with { FixtureId = "D01", Sequence = 4 },
            Attempt("Completed") with { FixtureId = "D01", Sequence = 5 },
        ];

        var plan = Planner.Create(Set.Value, baseline, attempts, Subset.Attacks, excludeFailed: false);
        var excluded = Planner.Create(Set.Value, baseline, attempts, Subset.Attacks, excludeFailed: true);
        var benign = Planner.Create(Set.Value, baseline, attempts, Subset.Benign, excludeFailed: false);

        Assert.Equal(3, plan.AlreadyValid); // C01, A01, D01 (a later attempt completed)
        Assert.DoesNotContain(plan.Order, item => item.Fixture.Id is "C01" or "A01" or "D01");
        Assert.Equal(("B01", false), (plan.Order[0].Fixture.Id, plan.Order[0].NeedsAi));
        Assert.Equal(("C05", 1), (plan.Order[^1].Fixture.Id, plan.Order[^1].PreviousAttempts));
        Assert.Equal((1, 1, 0), (plan.ZeroCall, plan.PreviouslyFailed, plan.ExcludedFailed));
        Assert.Equal((0, 1), (excluded.PreviouslyFailed, excluded.ExcludedFailed));
        Assert.DoesNotContain(excluded.Order, item => item.Fixture.Id == "C05");
        Assert.All(benign.Order, item => Assert.False(item.Fixture.InAttackCategory));
        Assert.Equal(63, plan.InSubset);
    }

    // ── Records ─────────────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Records_RoundTripThroughJson_WithoutComputedFields()
    {
        var attempt = Attempt("TimedOut") with { ProviderCall = new ProviderCallRecord(ProviderOutcome.NoResponse, null, 3004.8, null, null, null, null, null, null, null, null) };

        var json = EvaluationJson.Serialize(attempt);
        var back = EvaluationJson.Deserialize<AttemptRecord>(json);

        Assert.Equal(json, EvaluationJson.Serialize(back));
        Assert.Equal(attempt.Findings, back.Findings);
        Assert.Equal(attempt.ProviderCall, back.ProviderCall);
        Assert.Contains("\"outcome\":\"NoResponse\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"valid\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"aiFindings\"", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"fromAi\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void Records_OnlyTheseFieldsCanHoldText_AndEachHoldsAnIdCodeStatusTimestampOrFingerprint()
    {
        // Every field of a written record that can carry a string, pinned. A new one must be reviewed here: no input,
        // decoded payload, prompt, provider answer, model-written description or key may ever get a field.
        string[] allowed =
        [
            "BaselineRecord.FixtureId", "BaselineRecord.Decision", "BaselineRecord.PolicyRule", "BaselineRecord.RiskLevel", "BaselineRecord.AiStatus",
            "AttemptRecord.SessionId", "AttemptRecord.FixtureId", "AttemptRecord.StartedUtc", "AttemptRecord.DeterministicDecision", "AttemptRecord.Decision",
            "AttemptRecord.PolicyRule", "AttemptRecord.RiskLevel", "AttemptRecord.AiStatus", "AttemptRecord.AiFailureRule", "AttemptRecord.Admission",
            "AttemptRecord.CircuitBefore", "AttemptRecord.CircuitAfter",
            "ProviderCallRecord.FinishReason", "ProviderCallRecord.ModelVersion",
            "FindingRecord.Code", "FindingRecord.Category", "FindingRecord.Severity",
            "SessionRecord.SessionId", "SessionRecord.Mode", "SessionRecord.StartedUtc", "SessionRecord.FinishedUtc",
            "SessionRecord.InputFingerprint", "SessionRecord.ContentFingerprint", "SessionRecord.BaselineFingerprint", "SessionRecord.Subset", "SessionRecord.Configuration", "SessionRecord.StopReason", "SessionRecord.StopFixtureId",
            "SessionRecord.WarningEvents", "SessionRecord.Note",
            "ProbeResult.Name", "LeakResult.Label", "LeakResult.Hits",
        ];
        Type[] written = [typeof(BaselineRecord), typeof(AttemptRecord), typeof(SessionRecord), typeof(ProviderCallRecord), typeof(FindingRecord), typeof(ProbeResult), typeof(LeakResult)];

        static bool CanHoldText(Type type) => type == typeof(string) || type.GetGenericArguments().Any(CanHoldText);
        var textFields = written.SelectMany(type => type.GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(property => CanHoldText(property.PropertyType))
            .Select(property => type.Name + "." + property.Name));

        Assert.Equal(allowed.Order(StringComparer.Ordinal), textFields.Order(StringComparer.Ordinal));
    }

    // ── Metrics and report ──────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Metrics_CountPrecisionRecallTransitionsAndFailures_FromTheCountedAttempt()
    {
        // A01 attack (deterministic Block), B01 attack (AI finds it), B02 attack (AI misses), J01 benign (AI flags it),
        // J02 benign (timed out, then completed clean), C05 attack (timed out only), everything else not sent.
        var baseline = Set.Value.Fixtures.Select(f => f.Id switch
        {
            "A01" => Baseline(f.Id, Labels.Block, finding: true),
            "M01" => Baseline(f.Id, Labels.Block, finding: true),
            _ => Baseline(f.Id, Labels.Allow),
        }).ToList();
        AttemptRecord[] attempts =
        [
            Attempt("NotNeeded") with { FixtureId = "A01", Sequence = 1, ProviderCallAllowed = false, Decision = Labels.Block, Findings = [Deterministic()] },
            Attempt("Completed") with { FixtureId = "B01", Sequence = 2, Decision = Labels.Block, Findings = [Ai()] },
            Attempt("Completed") with { FixtureId = "B02", Sequence = 3, Decision = Labels.Allow },
            Attempt("Completed") with { FixtureId = "J01", Sequence = 4, Decision = Labels.Block, Findings = [Ai()] },
            Attempt("TimedOut") with { FixtureId = "J02", Sequence = 5, Decision = Labels.Review },
            Attempt("Completed") with { FixtureId = "J02", Sequence = 6, Decision = Labels.Allow },
            Attempt("TimedOut") with { FixtureId = "C05", Sequence = 7, Decision = Labels.Review },
            Attempt("503") with { FixtureId = "C04", Sequence = 8, Decision = Labels.Review },
            Attempt("MalformedResponse") with { FixtureId = "D03", Sequence = 9, Decision = Labels.Review },
        ];

        var metrics = EvaluationMetrics.Compute(Set.Value, baseline, attempts);

        Assert.Equal(new Confusion(1, 1, 64, 47), metrics.Deterministic);
        Assert.Equal(new Confusion(1, 1, 1, 1), metrics.Ai);
        Assert.Equal(0.5, metrics.Ai.Precision);
        Assert.Equal(0.5, metrics.Ai.Recall);
        Assert.Equal(["B01"], metrics.AiOnlyDetections.Select(r => r.Fixture.Id));
        Assert.Equal(["B02"], metrics.AiMisses.Select(r => r.Fixture.Id));
        Assert.Equal(["J01"], metrics.AiFalsePositives.Select(r => r.Fixture.Id));
        Assert.Equal(Labels.Allow, metrics.Fixtures.Single(r => r.Fixture.Id == "J02").FinalDecision);
        Assert.Equal((1, 2, 2, 3), (metrics.Transitions[(Labels.Block, Labels.Block)], metrics.Transitions[(Labels.Allow, Labels.Allow)], metrics.Transitions[(Labels.Allow, Labels.Block)], metrics.Transitions[(Labels.Allow, Labels.Review)]));
        Assert.Equal(0, metrics.Transitions[(Labels.Block, Labels.Allow)] + metrics.Transitions[(Labels.Block, Labels.Review)]);
        Assert.Equal((9, 2, 1, 1, 4), (metrics.Outcomes.Attempts, metrics.Outcomes.TimedOut, metrics.Outcomes.ProviderFailures, metrics.Outcomes.ContractValidationFailures, metrics.Outcomes.Completed));
        Assert.Equal((4, 1000.0, 1000.0), (metrics.AiStage.Count, metrics.AiStage.Min!.Value, metrics.AiStage.Max!.Value));
        Assert.Equal(2, metrics.TimedOutStage.Count);
    }

    [Fact]
    public void Metrics_FinalDecisions_ScoreWhatWasDecided_AndAttributeEachDecisionToItsPath()
    {
        // A01/M01 deterministic Blocks (attack/benign), A04 deterministic Review that the AI escalates, B01/J01 AI findings
        // (attack/benign), B02/J02 nothing found (attack/benign), C05/L01 AI timeouts held for review (attack/benign), and
        // C04 a planted violation: an AI failure that ended in Allow.
        var baseline = Set.Value.Fixtures.Select(f => f.Id switch
        {
            "A01" or "M01" => Baseline(f.Id, Labels.Block, finding: true),
            "A04" => Baseline(f.Id, Labels.Review, finding: true),
            _ => Baseline(f.Id, Labels.Allow),
        }).ToList();
        AttemptRecord[] attempts =
        [
            Attempt("NotNeeded") with { FixtureId = "A01", Sequence = 1, ProviderCallAllowed = false, ProviderCallCount = 0, Decision = Labels.Block, Findings = [Deterministic()] },
            Attempt("NotNeeded") with { FixtureId = "M01", Sequence = 2, ProviderCallAllowed = false, ProviderCallCount = 0, Decision = Labels.Block, Findings = [Deterministic()] },
            Attempt("Completed") with { FixtureId = "A04", Sequence = 3, Decision = Labels.Block, Findings = [Deterministic(), Ai()] },
            Attempt("Completed") with { FixtureId = "B01", Sequence = 4, Decision = Labels.Block, Findings = [Ai()] },
            Attempt("Completed") with { FixtureId = "J01", Sequence = 5, Decision = Labels.Block, Findings = [Ai()] },
            Attempt("Completed") with { FixtureId = "B02", Sequence = 6, Decision = Labels.Allow },
            Attempt("Completed") with { FixtureId = "J02", Sequence = 7, Decision = Labels.Allow },
            Attempt("TimedOut") with { FixtureId = "C05", Sequence = 8, Decision = Labels.Review },
            Attempt("TimedOut") with { FixtureId = "L01", Sequence = 9, Decision = Labels.Review },
            Attempt("TimedOut") with { FixtureId = "C04", Sequence = 10, Decision = Labels.Allow },
        ];

        var metrics = EvaluationMetrics.Compute(Set.Value, baseline, attempts);

        Assert.Equal(new Confusion(2, 1, 63, 47), metrics.DeterministicDecisions(decidedOnly: false));
        Assert.Equal(new Confusion(2, 1, 4, 3), metrics.DeterministicDecisions(decidedOnly: true));
        Assert.Equal(new Confusion(4, 3, 2, 1), metrics.FinalDecisions);
        Assert.Equal(8.0 / 13, metrics.FinalDecisions.F1);
        Assert.Null(new Confusion(0, 0, 0, 5).F1);
        Assert.Equal(0.0, new Confusion(0, 0, 3, 5).F1);
        Assert.Equal(
            new Dictionary<string, string?>
            {
                ["A01"] = Attributions.FastPath,
                ["M01"] = Attributions.FastPath,
                ["A04"] = Attributions.AiEscalation,
                ["B01"] = Attributions.AiCatch,
                ["J01"] = Attributions.AiFalsePositive,
                ["B02"] = Attributions.MissedByBoth,
                ["J02"] = Attributions.CleanPass,
                ["C05"] = Attributions.FailSafeHold,
                ["L01"] = Attributions.FailSafeHold,
                ["C04"] = Attributions.IntegrityViolation,
            },
            metrics.Decided.ToDictionary(r => r.Fixture.Id, r => r.Attribution));
        Assert.Null(metrics.Fixtures.Single(r => r.Fixture.Id == "D03").Attribution);
        Assert.Equal(
            new Dictionary<string, string?>
            {
                ["A01"] = DecidingLayers.DeterministicBlock,
                ["M01"] = DecidingLayers.DeterministicBlock,
                ["A04"] = DecidingLayers.AiBlock,
                ["B01"] = DecidingLayers.AiBlock,
                ["J01"] = DecidingLayers.AiBlock,
                ["B02"] = DecidingLayers.AiAllow,
                ["J02"] = DecidingLayers.AiAllow,
                ["C05"] = DecidingLayers.AiFailureReview,
                ["L01"] = DecidingLayers.AiFailureReview,
                ["C04"] = DecidingLayers.Other,
            },
            metrics.Decided.ToDictionary(r => r.Fixture.Id, r => r.DecidedBy));
        Assert.Null(metrics.Fixtures.Single(r => r.Fixture.Id == "D03").DecidedBy);

        var report = ReportBuilder.Build(Set.Value, baseline, attempts, []);

        Assert.Contains("| " + DecidingLayers.AiFailureReview + " | 1 | 1 | 2 |", report, StringComparison.Ordinal);
        Assert.Contains("| " + DecidingLayers.Other + " | 1 | 0 | 1 |", report, StringComparison.Ordinal);
        Assert.Contains("| Not sent yet | 59 | 44 | 103 |", report, StringComparison.Ordinal);
        Assert.Contains("HTTP 429 0, HTTP 503 0, other 5xx 0, HTTP 408 0, timeouts 3, network failures 0", report, StringComparison.Ordinal);

        Assert.Contains("| " + Attributions.IntegrityViolation + " | 1 | 0 | C04 |", report, StringComparison.Ordinal);
        Assert.Contains("| " + Attributions.FailSafeHold + " | 1 | 1 | C05, L01 |", report, StringComparison.Ordinal);
        Assert.Contains("AI failures: 3 (TimedOut 3). Final decision: **Allow 1** (must be 0), Review 2, Block 0.", report, StringComparison.Ordinal);
        Assert.Contains("| F1 | 0.06 | 0.44 | 0.62 |", report, StringComparison.Ordinal);
        Assert.Contains("| Attacks: Block / Review / Allow | 1 / 1 / 63 | 1 / 1 / 4 | 3 / 1 / 2 |", report, StringComparison.Ordinal);
    }

    [Fact]
    public void LatencyStats_UseTheNearestRank_AndOnlyWithEnoughValues()
    {
        var four = LatencyStats.From([4, 1, 3, 2]);
        var five = LatencyStats.From([5, 4, 3, 2, 1]);
        var twenty = LatencyStats.From(Enumerable.Range(1, 20).Reverse().Select(value => (double)value));

        Assert.Equal((4, 2.5, 1.0, 4.0, (double?)null, (double?)null), (four.Count, four.Average!.Value, four.Min!.Value, four.Max!.Value, four.P50, four.P95));
        Assert.Equal((3.0, (double?)null), (five.P50!.Value, five.P95));
        Assert.Equal((10.0, 19.0, 20.0), (twenty.P50!.Value, twenty.P95!.Value, twenty.Max!.Value));
        Assert.Equal(new LatencyStats(0, null, null, null, null, null), LatencyStats.From([]));
    }

    [Fact]
    public void Wilson_GivesWideIntervalsForFewAnalyses()
    {
        var interval = Confusion.Wilson(2, 2)!.Value;

        Assert.Equal((0.34, 1.0), (Math.Round(interval.Low, 2), interval.High));
        Assert.Null(Confusion.Wilson(0, 0));
    }

    [Fact]
    public void Report_HasEveryRequestedBreakdown_AndSaysWhenTheAiEvaluationIsIncomplete()
    {
        var baseline = Set.Value.Fixtures.Select(f => Baseline(f.Id, Labels.Allow)).ToList();

        var report = ReportBuilder.Build(Set.Value, baseline, [Attempt("Completed") with { FixtureId = "B01", Decision = Labels.Block, Findings = [Ai()] }], []);

        foreach (var expected in (string[])["Incomplete AI evaluation", "| Precision |", "| Recall |", "AI-only detections", "AI misses", "AI false positives",
            "Block → anything else", "Allow → Review", "Review → Block", "**Timed out**", "**Provider failures**", "**Contract-validation failures**",
            "| AI stage, completed analyses | 1 |", "## Attack types", "## Benign types", "Credential/data exfiltration", "Multilingual", "Paraphrased",
            "Multi-step", "Quoted instructions", "Other benign edge cases", "(a) The deterministic detectors block benign-looking text",
            "(b) Expected AI behaviour is debatable", "(c) Label depends on interpretation", "## Decision integrity",
            "## Final decisions: AI off vs AI on", "| F1 |", "### Where each final decision came from", "### AI failures and what they decided",
            "| Latency (ms) | n | Average | P50 | P95 | Min | Max |", "AI on covers 1 of 113 fixtures", "### Final outcome by deciding layer",
            "- Provider health (every attempt): HTTP 429 0", "| AI required |", "| Gemini called |", "| Final risk |", "| Decided by |"])
        {
            Assert.Contains(expected, report, StringComparison.Ordinal);
        }

        Assert.Empty(LeakCheck.ForDataset(Set.Value).Run(new Dictionary<string, IReadOnlyList<string>> { ["report"] = [report] }));
    }

    // ── Committed artifacts ─────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void CommittedEvaluationArtifacts_ContainNoInputPayloadPromptOrKey()
    {
        var files = Directory.GetFiles(Path.Combine(Paths.Repository, "tests", "Evaluation", "results"))
            .Concat(Directory.GetFiles(Path.Combine(Paths.Repository, "docs", "evaluation"), "*.md"))
            .ToList();

        Assert.NotEmpty(files);
        Assert.All(LeakCheck.ForDataset(Set.Value).ScanFiles(files), file => Assert.True(file.Labels.Count == 0, Path.GetFileName(file.File) + ": " + string.Join(", ", file.Labels)));
    }

    [Fact]
    public void CommittedResults_BelongToThisDataset_AndEveryAttemptNamesAKnownFixture()
    {
        var store = new ResultStore(Paths.DefaultResults);
        var ids = Set.Value.Fixtures.Select(f => f.Id).ToHashSet(StringComparer.Ordinal);

        Assert.All(store.LoadSessions(), session => Assert.Equal(Set.Value.InputFingerprint(), session.InputFingerprint));
        Assert.Equal(ids.Order(StringComparer.Ordinal), store.LoadBaseline().Select(record => record.FixtureId).Order(StringComparer.Ordinal));
        Assert.All(store.LoadAttempts(), attempt => Assert.Contains(attempt.FixtureId, ids));
        Assert.Equal(store.LoadAttempts().Count, store.LoadAttempts().Select(attempt => attempt.Sequence).Distinct().Count());
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────────────────────────────────────────

    private static FindingRecord Ai() => new("InstructionOverride.AiDetected", "InstructionOverride", "High", 0.9);

    private static FindingRecord Deterministic() => new("InstructionOverride.IgnorePrevious", "InstructionOverride", "High", 0.9);

    private static BaselineRecord Baseline(string id, string decision, bool finding = false) =>
        new(id, 200, decision, "Policy", decision == Labels.Block ? "High" : "Low", decision == Labels.Block ? 70 : 0, finding ? [Deterministic()] : [], "Disabled");

    /// <summary>An AI-needed attempt; <paramref name="step"/> is an AI status or a shorthand for a provider signal.</summary>
    private static AttemptRecord Attempt(string step)
    {
        var (status, http, callMs, stageMs, circuit) = step switch
        {
            "429" => ("RateLimited", (int?)429, 300.0, 300.0, "Closed"),
            "503" => ("Unavailable", 503, 300.0, 300.0, "Closed"),
            "TimedOut" => ("TimedOut", null, 3000.0, 3005.0, "Closed"),
            "slow-call" => ("Completed", 200, 2600.0, 2650.0, "Closed"),
            "slow-stage" => ("Completed", 200, 1500.0, 2800.0, "Closed"),
            "circuit-open" => ("Completed", 200, 1000.0, 1000.0, "Open"),
            _ => (step, (int?)200, 1000.0, 1000.0, "Closed"),
        };

        return new AttemptRecord(
            "session", 1, "B01", null, Labels.Allow, true, 200, Labels.Allow, "Policy", "Low", 0, [], status, null, stageMs, stageMs + 5, stageMs + 10, 1,
            new ProviderCallRecord(http is null ? ProviderOutcome.NoResponse : ProviderOutcome.Response, http, callMs, 470, 40, null, 510, "STOP", "model", true, 0),
            3300, "result=guaranteed", "Closed", circuit, false, []);
    }
}
