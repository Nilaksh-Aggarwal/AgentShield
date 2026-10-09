using AgentShield.Domain.Threats;
using AgentShield.Security.Aggregation;

namespace AgentShield.SecurityTests.Aggregation;

public class FindingAggregatorTests
{
    private readonly FindingAggregator _aggregator = new();

    [Fact]
    public void Aggregate_NoFindings_ReturnsEmpty()
    {
        Assert.Empty(_aggregator.Aggregate([]));
    }

    [Fact]
    public void Aggregate_DistinctFindings_AreAllKeptUnchanged()
    {
        var first = Finding("InstructionOverride.A", ThreatCategory.InstructionOverride, ThreatSeverity.High);
        var second = Finding("SecretExtraction.B", ThreatCategory.SecretExtraction, ThreatSeverity.High);

        var result = _aggregator.Aggregate([second, first]);

        Assert.Equal([first, second], result);
        Assert.All(result, finding => Assert.Empty(finding.CorroboratingEvidence));
    }

    [Fact]
    public void Aggregate_SameCodeFromTwoDetectors_BecomesOneFindingWithBothEvidence()
    {
        var fromA = Finding("InstructionOverride.X", severity: ThreatSeverity.High, confidence: 0.8, detector: "A", ruleId: "A-1");
        var fromB = Finding("InstructionOverride.X", severity: ThreatSeverity.High, confidence: 0.8, detector: "B", ruleId: "B-1");

        var fused = Assert.Single(_aggregator.Aggregate([fromB, fromA]));

        Assert.Equal("InstructionOverride.X", fused.Code);
        Assert.Equal(new FindingEvidence("A", "A-1", 1), fused.Evidence);
        Assert.Equal([new FindingEvidence("B", "B-1", 1)], fused.CorroboratingEvidence);
    }

    [Fact]
    public void Aggregate_DuplicatesWithDifferentSeverities_KeepHighestSeverityAndItsDescription()
    {
        var medium = Finding("Code.X", severity: ThreatSeverity.Medium, confidence: 0.6, detector: "A", description: "Medium view.");
        var critical = Finding("Code.X", severity: ThreatSeverity.Critical, confidence: 0.5, detector: "Z", description: "Critical view.");

        var fused = Assert.Single(_aggregator.Aggregate([medium, critical]));

        Assert.Equal(ThreatSeverity.Critical, fused.Severity);
        Assert.Equal("Critical view.", fused.Description);
        Assert.Equal("Z", fused.Evidence.Detector);
    }

    [Fact]
    public void Aggregate_DuplicatesWithDifferentConfidences_KeepTheHighestNotACombination()
    {
        var fused = Assert.Single(_aggregator.Aggregate(
        [
            Finding("Code.X", confidence: 0.6, detector: "A"),
            Finding("Code.X", confidence: 0.7, detector: "B"),
            Finding("Code.X", confidence: 0.5, detector: "C"),
        ]));

        Assert.Equal(0.7, fused.Confidence);
    }

    [Fact]
    public void Aggregate_IdenticalDuplicates_KeepOneCopyOfTheEvidence()
    {
        var finding = Finding("Code.X");

        var fused = Assert.Single(_aggregator.Aggregate([finding, finding, Finding("Code.X")]));

        Assert.Empty(fused.CorroboratingEvidence);
    }

    [Fact]
    public void Aggregate_SameCodeInDifferentCategories_IsNotMerged()
    {
        var result = _aggregator.Aggregate(
        [
            Finding("Shared.Code", ThreatCategory.InstructionOverride),
            Finding("Shared.Code", ThreatCategory.SecretExtraction),
        ]);

        Assert.Equal(2, result.Count);
    }

    [Fact]
    public void Aggregate_SameCategoryDifferentCodes_AreBothKept()
    {
        var result = _aggregator.Aggregate([Finding("Obfuscation.A", ThreatCategory.Obfuscation), Finding("Obfuscation.B", ThreatCategory.Obfuscation)]);

        Assert.Equal(["Obfuscation.A", "Obfuscation.B"], result.Select(finding => finding.Code));
    }

    [Fact]
    public void Aggregate_Order_IsSeverityThenCategoryThenCode()
    {
        var result = _aggregator.Aggregate(
        [
            Finding("Z.Low", ThreatCategory.InstructionOverride, ThreatSeverity.Low),
            Finding("B.High", ThreatCategory.Obfuscation, ThreatSeverity.High),
            Finding("C.High", ThreatCategory.InstructionOverride, ThreatSeverity.High),
            Finding("A.High", ThreatCategory.SecretExtraction, ThreatSeverity.High),
            Finding("A.Critical", ThreatCategory.RoleManipulation, ThreatSeverity.Critical),
            Finding("B.High2", ThreatCategory.InstructionOverride, ThreatSeverity.High),
        ]);

        Assert.Equal(["A.Critical", "B.High2", "C.High", "A.High", "B.High", "Z.Low"], result.Select(finding => finding.Code));
    }

    [Fact]
    public void Aggregate_EveryPermutationOfTheInput_YieldsTheSameResult()
    {
        ThreatFinding[] findings =
        [
            Finding("Code.X", severity: ThreatSeverity.High, confidence: 0.8, detector: "A", ruleId: "R-1"),
            Finding("Code.X", severity: ThreatSeverity.High, confidence: 0.8, detector: "B", ruleId: "R-2"),
            Finding("Code.X", severity: ThreatSeverity.Medium, confidence: 0.9, detector: "C", ruleId: "R-3"),
            Finding("Code.Y", ThreatCategory.SecretExtraction, ThreatSeverity.Critical),
            Finding("Code.Z", ThreatCategory.Obfuscation, ThreatSeverity.Low),
        ];

        var expected = Describe(_aggregator.Aggregate(findings));

        foreach (var permutation in Permutations(findings))
        {
            Assert.Equal(expected, Describe(_aggregator.Aggregate(permutation)));
        }
    }

    [Fact]
    public void Aggregate_AlreadyAggregatedFindings_AreStable()
    {
        ThreatFinding[] findings = [Finding("Code.X", detector: "A"), Finding("Code.X", detector: "B"), Finding("Code.Y")];

        var once = _aggregator.Aggregate(findings);
        var twice = _aggregator.Aggregate(once);

        Assert.Equal(Describe(once), Describe(twice));
    }

    [Fact]
    public void Aggregate_TiedDuplicates_FollowTheDocumentedRepresentativeAndEvidenceOrder_InEveryInputOrder()
    {
        // Audit data only, but specified (FindingAggregator remarks): among duplicates of equal severity the representative
        // is the most confident, then the smallest (detector, rule ID), then the highest match count, then the description;
        // corroborating evidence is ordered by detector, rule ID and match count (highest first). Mutation testing showed
        // that no test pinned these tie-breaks: every input order must give the same, documented result.
        static ThreatFinding Tied(string detector, string ruleId, int matches, string description, double confidence = 0.9) =>
            new("Test.Code", ThreatCategory.InstructionOverride, ThreatSeverity.High, confidence, description, new FindingEvidence(detector, ruleId, matches));
        ThreatFinding[] findings =
        [
            Tied("Zeta", "R-1", 1, "From Zeta."),
            Tied("Alpha", "R-2", 5, "From Alpha R-2."),
            Tied("Alpha", "R-1", 2, "B description."),
            Tied("Alpha", "R-1", 3, "C description."),
            Tied("Alpha", "R-1", 3, "A description."),
            Tied("Aardvark", "R-0", 9, "Less confident.", confidence: 0.5),
        ];

        foreach (var order in Permutations(findings))
        {
            var fused = Assert.Single(_aggregator.Aggregate(order));

            Assert.Equal(("Alpha", "R-1", 3, "A description.", 0.9), (fused.Evidence.Detector, fused.Evidence.RuleId, fused.Evidence.MatchCount, fused.Description, fused.Confidence));
            Assert.Equal(
                ["Aardvark/R-0/9", "Alpha/R-1/2", "Alpha/R-2/5", "Zeta/R-1/1"],
                fused.CorroboratingEvidence.Select(evidence => $"{evidence.Detector}/{evidence.RuleId}/{evidence.MatchCount}"));
        }
    }

    [Fact]
    public void Aggregate_DuplicatesOfOneRule_KeepTheStrongestObservation_AndOrderTheRestByMatchCount_InEveryInputOrder()
    {
        // Same detector, rule, severity, confidence and description: only the match count tells them apart, and it alone
        // must decide (mutation testing: with it ignored, the result followed the input order).
        static ThreatFinding Observed(int matches) =>
            new("Test.Code", ThreatCategory.InstructionOverride, ThreatSeverity.High, 0.9, "Same description.", new FindingEvidence("Alpha", "R-1", matches));

        foreach (var order in Permutations([Observed(1), Observed(3), Observed(2)]))
        {
            var fused = Assert.Single(_aggregator.Aggregate(order));

            Assert.Equal(3, fused.Evidence.MatchCount);
            Assert.Equal([2, 1], fused.CorroboratingEvidence.Select(evidence => evidence.MatchCount));
        }
    }

    [Fact]
    public void Aggregate_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => _aggregator.Aggregate(null!));
    }

    private static ThreatFinding Finding(
        string code,
        ThreatCategory category = ThreatCategory.InstructionOverride,
        ThreatSeverity severity = ThreatSeverity.High,
        double confidence = 0.9,
        string detector = "Test",
        string ruleId = "T-1",
        string description = "Test finding.") =>
        new(code, category, severity, confidence, description, new FindingEvidence(detector, ruleId, 1));

    // Findings with corroborating evidence compare lists by reference; compare their content instead.
    private static string[] Describe(IEnumerable<ThreatFinding> findings) =>
    [
        .. findings.Select(finding =>
            $"{finding.Severity}|{finding.Category}|{finding.Code}|{finding.Confidence}|{finding.Description}|"
            + string.Join(",", finding.AllEvidence.Select(evidence => $"{evidence.Detector}/{evidence.RuleId}/{evidence.MatchCount}"))),
    ];

    private static IEnumerable<ThreatFinding[]> Permutations(ThreatFinding[] items)
    {
        if (items.Length <= 1)
        {
            yield return items;
            yield break;
        }

        for (var i = 0; i < items.Length; i++)
        {
            ThreatFinding[] rest = [.. items[..i], .. items[(i + 1)..]];
            foreach (var tail in Permutations(rest))
            {
                yield return [items[i], .. tail];
            }
        }
    }
}
