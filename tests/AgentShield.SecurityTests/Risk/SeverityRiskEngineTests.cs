using AgentShield.Domain.Risk;
using AgentShield.Domain.Threats;
using AgentShield.Security.Risk;

namespace AgentShield.SecurityTests.Risk;

public class SeverityRiskEngineTests
{
    private readonly SeverityRiskEngine _engine = new();

    [Fact]
    public void Assess_NoFindings_IsScoreZeroAndLow()
    {
        var risk = _engine.Assess([]);

        Assert.Equal(0, risk.Score);
        Assert.Equal(RiskLevel.Low, risk.Level);
    }

    [Theory]
    [InlineData(ThreatSeverity.Low, 10, RiskLevel.Low)]
    [InlineData(ThreatSeverity.Medium, 40, RiskLevel.Medium)]
    [InlineData(ThreatSeverity.High, 70, RiskLevel.High)]
    [InlineData(ThreatSeverity.Critical, 90, RiskLevel.Critical)]
    public void Assess_SingleFinding_ScoresTheBaseOfItsSeverity(ThreatSeverity severity, int expectedScore, RiskLevel expectedLevel)
    {
        var risk = _engine.Assess([Finding(severity)]);

        Assert.Equal(expectedScore, risk.Score);
        Assert.Equal(expectedLevel, risk.Level);
    }

    [Fact]
    public void Assess_AdditionalFindings_AddFivePointsEach()
    {
        var risk = _engine.Assess([Finding(ThreatSeverity.High, "A"), Finding(ThreatSeverity.Medium, "B"), Finding(ThreatSeverity.Low, "C")]);

        Assert.Equal(80, risk.Score);
        Assert.Equal(RiskLevel.High, risk.Level);
    }

    [Theory]
    [InlineData(ThreatSeverity.Low, 29, RiskLevel.Low)]
    [InlineData(ThreatSeverity.Medium, 69, RiskLevel.Medium)]
    [InlineData(ThreatSeverity.High, 89, RiskLevel.High)]
    [InlineData(ThreatSeverity.Critical, 100, RiskLevel.Critical)]
    public void Assess_ManyFindings_NeverRaiseTheLevelAboveTheHighestSeverity(ThreatSeverity severity, int cappedScore, RiskLevel level)
    {
        var findings = Enumerable.Range(0, 20).Select(index => Finding(severity, $"Test.F{index}")).ToArray();

        var risk = _engine.Assess(findings);

        Assert.Equal(cappedScore, risk.Score);
        Assert.Equal(level, risk.Level);
    }

    [Fact]
    public void Assess_IsIndependentOfFindingOrder()
    {
        ThreatFinding[] findings = [Finding(ThreatSeverity.Low, "A"), Finding(ThreatSeverity.Critical, "B"), Finding(ThreatSeverity.Medium, "C")];

        var forward = _engine.Assess(findings);
        var reversed = _engine.Assess([.. findings.Reverse()]);

        Assert.Equal(forward, reversed);
        Assert.Equal(new RiskAssessment(100), forward);
    }

    [Fact]
    public void Assess_ConfidenceDoesNotChangeTheScore()
    {
        var sure = _engine.Assess([Finding(ThreatSeverity.High, confidence: 1.0)]);
        var unsure = _engine.Assess([Finding(ThreatSeverity.High, confidence: 0.1)]);

        Assert.Equal(sure, unsure);
    }

    private static ThreatFinding Finding(ThreatSeverity severity, string code = "Test.Finding", double confidence = 0.9) =>
        new(code, ThreatCategory.InstructionOverride, severity, confidence, "Test finding.", new FindingEvidence("T-1", 1));
}
