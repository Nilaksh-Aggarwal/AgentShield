using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.Threats;
using AgentShield.Security.Policy;

namespace AgentShield.SecurityTests.Policy;

public class RiskThresholdPolicyEngineTests
{
    private static readonly ThreatFinding[] OneFinding =
        [new("Test.Finding", ThreatCategory.SecretExtraction, ThreatSeverity.Low, 0.5, "Test finding.", new FindingEvidence("T-1", 1))];

    private readonly RiskThresholdPolicyEngine _policy = new();

    [Theory]
    [InlineData(10, SecurityDecision.Allow, RiskThresholdPolicyEngine.AllowLowRisk)]
    [InlineData(29, SecurityDecision.Allow, RiskThresholdPolicyEngine.AllowLowRisk)]
    [InlineData(30, SecurityDecision.Review, RiskThresholdPolicyEngine.ReviewMediumRisk)]
    [InlineData(69, SecurityDecision.Review, RiskThresholdPolicyEngine.ReviewMediumRisk)]
    [InlineData(70, SecurityDecision.Block, RiskThresholdPolicyEngine.BlockHighRisk)]
    [InlineData(89, SecurityDecision.Block, RiskThresholdPolicyEngine.BlockHighRisk)]
    [InlineData(90, SecurityDecision.Block, RiskThresholdPolicyEngine.BlockHighRisk)]
    [InlineData(100, SecurityDecision.Block, RiskThresholdPolicyEngine.BlockHighRisk)]
    public void Decide_MapsRiskBandsToDecisions(int score, SecurityDecision expected, string expectedRule)
    {
        var decision = _policy.Decide(new RiskAssessment(score), OneFinding);

        Assert.Equal(expected, decision.Decision);
        Assert.Equal(expectedRule, decision.RuleCode);
        Assert.False(string.IsNullOrWhiteSpace(decision.Reason));
    }

    [Fact]
    public void Decide_NoFindings_AllowsWithNoThreatsRule()
    {
        var decision = _policy.Decide(RiskAssessment.None, []);

        Assert.Equal(SecurityDecision.Allow, decision.Decision);
        Assert.Equal(RiskThresholdPolicyEngine.AllowNoThreats, decision.RuleCode);
    }

    [Fact]
    public void Decide_FollowsRiskLevelNotFindingCount()
    {
        // The risk engine owns scoring; the policy must not second-guess it by counting findings.
        var decision = _policy.Decide(new RiskAssessment(75), []);

        Assert.Equal(SecurityDecision.Block, decision.Decision);
    }
}
