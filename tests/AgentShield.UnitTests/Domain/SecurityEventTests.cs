using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.UnitTests.Domain;

public class SecurityEventTests
{
    private static readonly PolicyDecision Allow = new(SecurityDecision.Allow, "Policy.AllowNoThreats", "No threats were detected.");

    [Fact]
    public void Constructor_KeepsEventIdentityAndCorrelationIdSeparate()
    {
        var id = SecurityEventId.New();

        var securityEvent = new SecurityEvent(id, "req-42", DateTimeOffset.UnixEpoch, Allow, RiskAssessment.None, [], 12, TimeSpan.FromMilliseconds(3));

        Assert.Equal(id, securityEvent.Id);
        Assert.Equal("req-42", securityEvent.CorrelationId);
        Assert.NotEqual(id.ToString(), securityEvent.CorrelationId);
    }

    [Fact]
    public void Constructor_DefaultId_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            new SecurityEvent(default, "req-42", DateTimeOffset.UnixEpoch, Allow, RiskAssessment.None, [], 12, TimeSpan.Zero));
    }

    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    public void Constructor_BlankCorrelationId_Throws(string correlationId)
    {
        Assert.ThrowsAny<ArgumentException>(() =>
            new SecurityEvent(SecurityEventId.New(), correlationId, DateTimeOffset.UnixEpoch, Allow, RiskAssessment.None, [], 12, TimeSpan.Zero));
    }

    [Fact]
    public void Constructor_NegativeLengthOrDuration_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new SecurityEvent(SecurityEventId.New(), "req", DateTimeOffset.UnixEpoch, Allow, RiskAssessment.None, [], -1, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new SecurityEvent(SecurityEventId.New(), "req", DateTimeOffset.UnixEpoch, Allow, RiskAssessment.None, [], 0, TimeSpan.FromTicks(-1)));
    }

    [Fact]
    public void PolicyDecision_RequiresRuleCodeReasonAndDefinedDecision()
    {
        Assert.ThrowsAny<ArgumentException>(() => new PolicyDecision(SecurityDecision.Block, "", "Reason."));
        Assert.ThrowsAny<ArgumentException>(() => new PolicyDecision(SecurityDecision.Block, "Policy.Rule", " "));
        Assert.Throws<ArgumentOutOfRangeException>(() => new PolicyDecision((SecurityDecision)0, "Policy.Rule", "Reason."));
    }
}
