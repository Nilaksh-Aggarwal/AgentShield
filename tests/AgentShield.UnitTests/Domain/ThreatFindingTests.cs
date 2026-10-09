using AgentShield.Domain.Threats;

namespace AgentShield.UnitTests.Domain;

public class ThreatFindingTests
{
    private static readonly FindingEvidence Evidence = new("T-1", 1);

    [Fact]
    public void Constructor_ValidValues_AreExposedUnchanged()
    {
        var finding = new ThreatFinding("Area.Reason", ThreatCategory.SecretExtraction, ThreatSeverity.High, 0.75, "Description.", Evidence);

        Assert.Equal("Area.Reason", finding.Code);
        Assert.Equal(ThreatCategory.SecretExtraction, finding.Category);
        Assert.Equal(ThreatSeverity.High, finding.Severity);
        Assert.Equal(0.75, finding.Confidence);
        Assert.Equal("Description.", finding.Description);
        Assert.Same(Evidence, finding.Evidence);
    }

    [Theory]
    [InlineData(-0.01)]
    [InlineData(1.01)]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    public void Constructor_ConfidenceOutsideZeroToOne_Throws(double confidence)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ThreatFinding("Area.Reason", ThreatCategory.SecretExtraction, ThreatSeverity.High, confidence, "Description.", Evidence));
    }

    [Theory]
    [InlineData(0.0)]
    [InlineData(1.0)]
    public void Constructor_ConfidenceAtBounds_IsAccepted(double confidence)
    {
        var finding = new ThreatFinding("Area.Reason", ThreatCategory.SecretExtraction, ThreatSeverity.Low, confidence, "Description.", Evidence);

        Assert.Equal(confidence, finding.Confidence);
    }

    [Fact]
    public void Constructor_UndefinedEnumValues_Throw()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ThreatFinding("Area.Reason", (ThreatCategory)0, ThreatSeverity.Low, 0.5, "Description.", Evidence));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new ThreatFinding("Area.Reason", ThreatCategory.SecretExtraction, (ThreatSeverity)99, 0.5, "Description.", Evidence));
    }

    [Theory]
    [InlineData("", "Description.")]
    [InlineData(" ", "Description.")]
    [InlineData("Area.Reason", "")]
    public void Constructor_BlankCodeOrDescription_Throws(string code, string description)
    {
        Assert.ThrowsAny<ArgumentException>(() =>
            new ThreatFinding(code, ThreatCategory.SecretExtraction, ThreatSeverity.Low, 0.5, description, Evidence));
    }

    [Fact]
    public void Severities_AreOrderedFromLowToCritical()
    {
        Assert.True(ThreatSeverity.Low < ThreatSeverity.Medium);
        Assert.True(ThreatSeverity.Medium < ThreatSeverity.High);
        Assert.True(ThreatSeverity.High < ThreatSeverity.Critical);
    }

    [Fact]
    public void Constructor_WithoutCorroboration_HasNoCorroboratingEvidence()
    {
        var finding = new ThreatFinding("Area.Reason", ThreatCategory.Obfuscation, ThreatSeverity.High, 0.9, "Description.", Evidence);

        Assert.Empty(finding.CorroboratingEvidence);
        Assert.Equal([Evidence], finding.AllEvidence);
    }

    [Fact]
    public void CorroboratingEvidence_IsExposedAfterThePrimaryEvidence()
    {
        var other = new FindingEvidence("B", "B-1", 2);

        var finding = new ThreatFinding("Area.Reason", ThreatCategory.Obfuscation, ThreatSeverity.High, 0.9, "Description.", Evidence)
        {
            CorroboratingEvidence = [other],
        };

        Assert.Equal([Evidence, other], finding.AllEvidence);
    }

    [Fact]
    public void CorroboratingEvidence_NullOrContainingNull_Throws()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new ThreatFinding("Area.Reason", ThreatCategory.Obfuscation, ThreatSeverity.High, 0.9, "D.", Evidence) { CorroboratingEvidence = null! });
        Assert.Throws<ArgumentException>(() =>
            new ThreatFinding("Area.Reason", ThreatCategory.Obfuscation, ThreatSeverity.High, 0.9, "D.", Evidence) { CorroboratingEvidence = [null!] });
    }

    [Fact]
    public void Evidence_WithDetector_RecordsIt_AndWithoutIsUnattributed()
    {
        Assert.Equal("InstructionOverride", new FindingEvidence("InstructionOverride", "IO-001", 1).Detector);
        Assert.Equal(FindingEvidence.UnattributedDetector, new FindingEvidence("IO-001", 1).Detector);
        Assert.NotEqual(new FindingEvidence("A", "R-1", 1), new FindingEvidence("B", "R-1", 1));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void Evidence_BlankDetector_Throws(string detector)
    {
        Assert.ThrowsAny<ArgumentException>(() => new FindingEvidence(detector, "R-1", 1));
    }

    [Theory]
    [InlineData("", 1)]
    [InlineData("T-1", 0)]
    [InlineData("T-1", -1)]
    public void Evidence_WithoutRuleOrMatch_Throws(string ruleId, int matchCount)
    {
        Assert.ThrowsAny<ArgumentException>(() => new FindingEvidence(ruleId, matchCount));
    }
}
