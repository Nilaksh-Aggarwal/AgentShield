using System.Globalization;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.Threats;
using AgentShield.Security.Aggregation;
using AgentShield.Security.Policy;
using AgentShield.Security.Risk;

namespace AgentShield.SecurityTests.DecisionCore;

/// <summary>
/// The decision core (fusion → risk → policy) checked exhaustively against an oracle written from the specification
/// (docs/security/firewall-pipeline.md, risk scoring and policy), not from the engines: every score, every multiset of up
/// to six severities, the exact count at which each band caps, and monotonicity — adding a finding never lowers the risk
/// or the decision, so a Block can never become Allow and a Review never becomes Allow. Every test runs the production
/// aggregator, risk engine and policy engine; the oracle only states the expected values.
/// </summary>
public class DecisionCoreBoundaryTests
{
    private const int MaxMultisetSize = 6;

    private static readonly ThreatSeverity[] Severities = [ThreatSeverity.Low, ThreatSeverity.Medium, ThreatSeverity.High, ThreatSeverity.Critical];

    private readonly FindingAggregator _aggregator = new();
    private readonly SeverityRiskEngine _risk = new();
    private readonly RiskThresholdPolicyEngine _policy = new();

    // ── Policy: every score ─────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Decide_EveryScoreFrom0To100_FollowsTheBandsExactly_WithAndWithoutFindings()
    {
        var failures = new List<string>();
        for (var score = RiskAssessment.MinScore; score <= RiskAssessment.MaxScore; score++)
        {
            var expected = ExpectedDecision(score);
            var withFindings = _policy.Decide(new RiskAssessment(score), [Finding(ThreatSeverity.Low)]);
            var withoutFindings = _policy.Decide(new RiskAssessment(score), []);

            Check(failures, score, expected, ExpectedRule(expected, hasFindings: true), withFindings);
            Check(failures, score, expected, ExpectedRule(expected, hasFindings: false), withoutFindings);
        }

        Assert.Empty(failures);
    }

    [Theory]
    [InlineData(29, SecurityDecision.Allow)]
    [InlineData(30, SecurityDecision.Review)]
    [InlineData(69, SecurityDecision.Review)]
    [InlineData(70, SecurityDecision.Block)]
    [InlineData(89, SecurityDecision.Block)]
    [InlineData(90, SecurityDecision.Block)]
    public void Decide_OnEitherSideOfEachThreshold_SwitchesExactlyThere(int score, SecurityDecision expected)
    {
        Assert.Equal(expected, _policy.Decide(new RiskAssessment(score), [Finding(ThreatSeverity.Medium)]).Decision);
    }

    // ── Risk: specification examples and every multiset ─────────────────────────────────────────────────────────────

    public static TheoryData<string, int, RiskLevel, SecurityDecision> SpecificationExamples() => new()
    {
        { "", 0, RiskLevel.Low, SecurityDecision.Allow },
        { "L", 10, RiskLevel.Low, SecurityDecision.Allow },
        { "LLLLL", 29, RiskLevel.Low, SecurityDecision.Allow },
        { "M", 40, RiskLevel.Medium, SecurityDecision.Review },
        { "LM", 45, RiskLevel.Medium, SecurityDecision.Review },
        { "MMMMMMM", 69, RiskLevel.Medium, SecurityDecision.Review },
        { "H", 70, RiskLevel.High, SecurityDecision.Block },
        { "LLLH", 85, RiskLevel.High, SecurityDecision.Block },
        { "LMHHH", 89, RiskLevel.High, SecurityDecision.Block },
        { "C", 90, RiskLevel.Critical, SecurityDecision.Block },
        { "CLL", 100, RiskLevel.Critical, SecurityDecision.Block },
    };

    [Theory]
    [MemberData(nameof(SpecificationExamples))]
    public void AssessAndDecide_SpecificationExamples(string severities, int score, RiskLevel level, SecurityDecision decision)
    {
        var findings = Findings(severities.Select(Parse));

        var risk = _risk.Assess(findings);

        Assert.Equal((score, level), (risk.Score, risk.Level));
        Assert.Equal(decision, _policy.Decide(risk, findings).Decision);
    }

    [Fact]
    public void Assess_EveryMultisetOfUpToSixSeverities_MatchesTheSpecification_InEveryOrder()
    {
        var failures = new List<string>();
        var checkedSets = 0;
        foreach (var multiset in Multisets(MaxMultisetSize))
        {
            var (score, level) = ExpectedRisk(multiset);
            ThreatSeverity[][] orders = [multiset, [.. multiset.AsEnumerable().Reverse()]];
            foreach (var order in orders)
            {
                var findings = Findings(order);
                var risk = _risk.Assess(findings);
                var decision = _policy.Decide(risk, findings).Decision;
                if (risk.Score != score || risk.Level != level || decision != ExpectedDecision(score))
                {
                    failures.Add(Invariant($"{Describe(order)}: got {risk.Score}/{risk.Level}/{decision}, expected {score}/{level}/{ExpectedDecision(score)}"));
                }
            }

            checkedSets++;
        }

        Assert.Empty(failures);
        Assert.Equal(210, checkedSets); // C(n + 3, 3) multisets for n = 0..6
    }

    [Theory]
    [InlineData(ThreatSeverity.Low, new[] { 10, 15, 20, 25, 29, 29, 29, 29 })]
    [InlineData(ThreatSeverity.Medium, new[] { 40, 45, 50, 55, 60, 65, 69, 69 })]
    [InlineData(ThreatSeverity.High, new[] { 70, 75, 80, 85, 89, 89, 89, 89 })]
    [InlineData(ThreatSeverity.Critical, new[] { 90, 95, 100, 100, 100, 100, 100, 100 })]
    public void Assess_FindingsOfOneSeverity_ScoreExactly_AndCapAtTheTopOfTheirBand(ThreatSeverity severity, int[] scoresForOneToEight)
    {
        var scores = Enumerable.Range(1, scoresForOneToEight.Length)
            .Select(count => _risk.Assess(Findings(Enumerable.Repeat(severity, count))).Score)
            .ToArray();

        Assert.Equal(scoresForOneToEight, scores);
    }

    [Theory]
    [InlineData(ThreatSeverity.Low, SecurityDecision.Allow)]
    [InlineData(ThreatSeverity.Medium, SecurityDecision.Review)]
    [InlineData(ThreatSeverity.High, SecurityDecision.Block)]
    public void Decide_AnyNumberOfFindingsOfOneSeverity_NeverCrossesIntoTheNextBand(ThreatSeverity severity, SecurityDecision decision)
    {
        // Volume is not severity: a thousand Low findings stay Allow, Medium never blocks, High never becomes Critical.
        var findings = Findings(Enumerable.Repeat(severity, 1_000));

        var risk = _risk.Assess(findings);

        Assert.Equal(decision, _policy.Decide(risk, findings).Decision);
        Assert.Equal((RiskLevel)(int)severity, risk.Level);
    }

    // ── Monotonicity ────────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AddingAFindingOfAnySeverity_ToEveryMultiset_NeverLowersTheScoreLevelOrDecision()
    {
        var failures = new List<string>();
        var (reviewsChecked, blocksChecked) = (0, 0);
        foreach (var multiset in Multisets(MaxMultisetSize - 1))
        {
            var before = Evaluate(Findings(multiset));
            reviewsChecked += before.Decision == SecurityDecision.Review ? Severities.Length : 0;
            blocksChecked += before.Decision == SecurityDecision.Block ? Severities.Length : 0;
            foreach (var added in Severities)
            {
                var after = Evaluate(Findings([.. multiset, added]));
                if (after.Risk.Score < before.Risk.Score || after.Risk.Level < before.Risk.Level || Strictness(after.Decision) < Strictness(before.Decision))
                {
                    failures.Add(Invariant($"{Describe(multiset)} + {added}: {before.Risk.Score}/{before.Decision} -> {after.Risk.Score}/{after.Decision}"));
                }
            }
        }

        Assert.Empty(failures);
        Assert.Equal((60, 420), (reviewsChecked, blocksChecked)); // starting Reviews and Blocks, each with 4 additions
    }

    [Fact]
    public void Pipeline_FusionRiskPolicy_AddingAnyFinding_NeverLowersTheDecision_AndABlockStaysBlock()
    {
        // Fixed seed: reproducible. The pool repeats codes (so fusion merges duplicates of different severities) and
        // mixes deterministic, AI and AI-failure codes, as the use case does before risk and policy.
        var random = new Random(20261001);
        (string Code, ThreatCategory Category)[] pool =
        [
            ("InstructionOverride.IgnorePrevious", ThreatCategory.InstructionOverride),
            ("RoleManipulation.ForgedRoleDelimiter", ThreatCategory.RoleManipulation),
            ("SecretExtraction.CredentialDisclosure", ThreatCategory.SecretExtraction),
            ("Obfuscation.EncodedThreat", ThreatCategory.Obfuscation),
            ("InstructionOverride.AiDetected", ThreatCategory.InstructionOverride),
            ("InconclusiveAnalysis.AiAnalysisIncomplete", ThreatCategory.InconclusiveAnalysis),
        ];
        ThreatFinding NextFinding()
        {
            var (code, category) = pool[random.Next(pool.Length)];
            return new ThreatFinding(code, category, Severities[random.Next(Severities.Length)], random.NextDouble(), "Test finding.", new FindingEvidence("T-" + random.Next(3), 1));
        }

        var failures = new List<string>();
        var (reviews, blocks) = (0, 0);
        for (var trial = 0; trial < 5_000; trial++)
        {
            var findings = Enumerable.Range(0, random.Next(9)).Select(_ => NextFinding()).ToList();
            var before = Evaluate(_aggregator.Aggregate(findings));
            var added = NextFinding();
            var after = Evaluate(_aggregator.Aggregate([.. findings, added]));

            reviews += before.Decision == SecurityDecision.Review ? 1 : 0;
            blocks += before.Decision == SecurityDecision.Block ? 1 : 0;
            if (after.Risk.Score < before.Risk.Score || Strictness(after.Decision) < Strictness(before.Decision))
            {
                failures.Add(Invariant($"trial {trial}: {before.Risk.Score}/{before.Decision} + {added.Code} {added.Severity} -> {after.Risk.Score}/{after.Decision}"));
            }
        }

        Assert.Empty(failures);
        Assert.True(reviews > 250 && blocks > 500, Invariant($"Only {reviews} starting Reviews and {blocks} starting Blocks were exercised."));
    }

    // ── The most severe finding decides; unknown and malformed values ──────────────────────────────────────────────────

    [Fact]
    public void EveryMultiset_ThroughTheAggregator_TheMostSevereFindingDecides_SoMediumIsNeverAllowedAndHighIsAlwaysBlocked()
    {
        // The findings share two codes, so fusion merges duplicates of different severities on the way, in both orders.
        var failures = new List<string>();
        foreach (var multiset in Multisets(MaxMultisetSize))
        {
            var expected = multiset.Length == 0 ? SecurityDecision.Allow : multiset.Max() switch
            {
                ThreatSeverity.Low => SecurityDecision.Allow,
                ThreatSeverity.Medium => SecurityDecision.Review,
                _ => SecurityDecision.Block,
            };
            ThreatSeverity[][] orders = [multiset, [.. multiset.AsEnumerable().Reverse()]];
            foreach (var order in orders)
            {
                var fused = _aggregator.Aggregate([.. order.Select((severity, index) => Finding(severity, index % 2 == 0 ? "Test.Even" : "Test.Odd"))]);
                var (_, decision) = Evaluate(fused);
                var keptHighest = order.Length == 0 || fused.Max(finding => finding.Severity) == order.Max();
                if (decision != expected || !keptHighest)
                {
                    failures.Add(Invariant($"{Describe(order)}: got {decision}, expected {expected}; highest severity kept: {keptHighest}"));
                }
            }
        }

        Assert.Empty(failures);
    }

    [Theory]
    [InlineData(ThreatSeverity.Low, SecurityDecision.Allow)]
    [InlineData(ThreatSeverity.Medium, SecurityDecision.Review)]
    [InlineData(ThreatSeverity.High, SecurityDecision.Block)]
    [InlineData(ThreatSeverity.Critical, SecurityDecision.Block)]
    public void FindingWithACodeNothingKnows_InEveryCategory_AtZeroConfidence_IsDecidedByItsSeverity_NeverIgnored(ThreatSeverity severity, SecurityDecision expected)
    {
        // A code from a future detector (or one the console has no text for) still counts: fusion, risk and policy read
        // its category, code and severity, never a catalogue, so an unrecognised finding cannot be dropped or downgraded.
        foreach (var category in Enum.GetValues<ThreatCategory>())
        {
            var findings = _aggregator.Aggregate([new ThreatFinding("Future.UnknownRule", category, severity, 0.0, "Unknown finding.", new FindingEvidence("X-999", 1))]);

            var (risk, decision) = Evaluate(findings);

            Assert.Equal((expected, (RiskLevel)(int)severity), (decision, risk.Level));
        }
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(-1)]
    [InlineData(int.MaxValue)]
    public void UndefinedSeverity_IsRejectedByTheFindingAndTheRiskEngine_NeverScoredAsLow(int value)
    {
        // A finding cannot carry an undefined severity, and the engine refuses one too instead of falling back to a low
        // score: an analysis that meets one fails closed (500, no decision, AnalyzeInputUseCaseTests), it is never allowed.
        var severity = (ThreatSeverity)value;

        Assert.Throws<ArgumentOutOfRangeException>(() => SeverityRiskEngine.BaseScoreFor(severity));
        Assert.Throws<ArgumentOutOfRangeException>(() => Finding(severity));
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(101)]
    [InlineData(int.MinValue)]
    public void RiskOutsideTheScale_CannotReachThePolicy(int score)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RiskAssessment(score));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────────────────────────────────────────

    // The specification, restated independently of the engines: the highest severity sets the band and its base score,
    // every further finding adds 5, and the score never leaves the band.
    private static (int Score, RiskLevel Level) ExpectedRisk(ThreatSeverity[] severities)
    {
        if (severities.Length == 0)
        {
            return (0, RiskLevel.Low);
        }

        var (baseScore, top, level) = severities.Max() switch
        {
            ThreatSeverity.Low => (10, 29, RiskLevel.Low),
            ThreatSeverity.Medium => (40, 69, RiskLevel.Medium),
            ThreatSeverity.High => (70, 89, RiskLevel.High),
            _ => (90, 100, RiskLevel.Critical),
        };
        return (Math.Min(baseScore + (5 * (severities.Length - 1)), top), level);
    }

    // How strict a decision is, stated here rather than read from the enum's numbers.
    private static int Strictness(SecurityDecision decision) => decision switch
    {
        SecurityDecision.Allow => 0,
        SecurityDecision.Review => 1,
        SecurityDecision.Block => 2,
        _ => throw new ArgumentOutOfRangeException(nameof(decision), decision, "Unknown decision."),
    };

    private static SecurityDecision ExpectedDecision(int score) =>
        score >= 70 ? SecurityDecision.Block : score >= 30 ? SecurityDecision.Review : SecurityDecision.Allow;

    private static string ExpectedRule(SecurityDecision decision, bool hasFindings) => decision switch
    {
        SecurityDecision.Block => RiskThresholdPolicyEngine.BlockHighRisk,
        SecurityDecision.Review => RiskThresholdPolicyEngine.ReviewMediumRisk,
        _ => hasFindings ? RiskThresholdPolicyEngine.AllowLowRisk : RiskThresholdPolicyEngine.AllowNoThreats,
    };

    private static void Check(List<string> failures, int score, SecurityDecision expected, string expectedRule, PolicyDecision actual)
    {
        if (actual.Decision != expected || actual.RuleCode != expectedRule || string.IsNullOrWhiteSpace(actual.Reason))
        {
            failures.Add(Invariant($"score {score}: got {actual.Decision}/{actual.RuleCode}, expected {expected}/{expectedRule}"));
        }
    }

    private (RiskAssessment Risk, SecurityDecision Decision) Evaluate(IReadOnlyList<ThreatFinding> findings)
    {
        var risk = _risk.Assess(findings);
        return (risk, _policy.Decide(risk, findings).Decision);
    }

    /// <summary>Every multiset (combination with repetition) of the four severities with 0 to <paramref name="maxSize"/> elements.</summary>
    private static IEnumerable<ThreatSeverity[]> Multisets(int maxSize)
    {
        for (var size = 0; size <= maxSize; size++)
        {
            foreach (var multiset in OfSize(size, 0))
            {
                yield return multiset;
            }
        }

        static IEnumerable<ThreatSeverity[]> OfSize(int size, int from)
        {
            if (size == 0)
            {
                yield return [];
                yield break;
            }

            for (var index = from; index < Severities.Length; index++)
            {
                foreach (var rest in OfSize(size - 1, index))
                {
                    yield return [Severities[index], .. rest];
                }
            }
        }
    }

    /// <summary>One finding per severity, each with its own code, so nothing is fused.</summary>
    private static ThreatFinding[] Findings(IEnumerable<ThreatSeverity> severities) =>
        [.. severities.Select((severity, index) => Finding(severity, Invariant($"Test.F{index}")))];

    private static ThreatFinding Finding(ThreatSeverity severity, string code = "Test.Finding") =>
        new(code, ThreatCategory.InstructionOverride, severity, 0.9, "Test finding.", new FindingEvidence("T-1", 1));

    private static ThreatSeverity Parse(char letter) => letter switch
    {
        'L' => ThreatSeverity.Low,
        'M' => ThreatSeverity.Medium,
        'H' => ThreatSeverity.High,
        _ => ThreatSeverity.Critical,
    };

    private static string Describe(IEnumerable<ThreatSeverity> severities) => "[" + string.Join(",", severities) + "]";

    private static string Invariant(FormattableString text) => text.ToString(CultureInfo.InvariantCulture);
}
