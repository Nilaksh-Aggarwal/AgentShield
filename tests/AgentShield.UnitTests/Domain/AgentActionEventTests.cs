using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.UnitTests.Domain;

public sealed class AgentActionEventTests
{
    private static readonly AgentActionAuthorization Verdict = new(
        AgentActionReason.HumanApprovalRequired,
        RiskLevel.High,
        new RecognisedAgentAction(new AgentId("support-agent"), new ToolId("email"), new ActionName("send"), new Capability("email:send")));

    [Fact]
    public void Constructor_KeepsTheVerdictIdentifiersAndInputDecision()
    {
        var id = SecurityEventId.New();
        var occurredAt = new DateTimeOffset(2026, 10, 7, 9, 0, 0, TimeSpan.Zero);

        var agentActionEvent = new AgentActionEvent(id, "corr-agent-1", occurredAt, Verdict, SecurityDecision.Allow, TimeSpan.FromMilliseconds(2));

        Assert.Equal((id, "corr-agent-1", occurredAt), (agentActionEvent.Id, agentActionEvent.CorrelationId, agentActionEvent.OccurredAt));
        Assert.Same(Verdict, agentActionEvent.Authorization);
        Assert.Equal(SecurityDecision.Allow, agentActionEvent.InputDecision);
        Assert.Equal(TimeSpan.FromMilliseconds(2), agentActionEvent.Duration);
    }

    [Fact]
    public void Constructor_RejectsAnIncompleteOrInvalidEvent()
    {
        var now = DateTimeOffset.UnixEpoch;

        Assert.Throws<ArgumentException>(() => new AgentActionEvent(default, "corr", now, Verdict, null, TimeSpan.Zero));
        Assert.ThrowsAny<ArgumentException>(() => new AgentActionEvent(SecurityEventId.New(), " ", now, Verdict, null, TimeSpan.Zero));
        Assert.Throws<ArgumentNullException>(() => new AgentActionEvent(SecurityEventId.New(), "corr", now, null!, null, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgentActionEvent(SecurityEventId.New(), "corr", now, Verdict, (SecurityDecision)9, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgentActionEvent(SecurityEventId.New(), "corr", now, Verdict, null, TimeSpan.FromTicks(-1)));
    }
}
