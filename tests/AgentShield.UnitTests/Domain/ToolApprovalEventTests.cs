using AgentShield.Domain.Agents;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.UnitTests.Domain;

/// <summary>
/// The audit entry for a person's decision (Milestone 13): only an approval a named person approved or denied is recorded
/// this way; a pending, used or withdrawn approval is not a person's decision.
/// </summary>
public sealed class ToolApprovalEventTests
{
    private static readonly DateTimeOffset At = new(2026, 10, 7, 12, 0, 0, TimeSpan.Zero);

    [Fact]
    public void Event_RecordsAnApprovalOrADenial_WithItsTrace()
    {
        var approved = new ToolApprovalEvent(Pending().Approve(At, "approver-console"), "corr-decide", At);
        var denied = new ToolApprovalEvent(Pending().Deny(At, "approver-console"), "corr-decide", At);

        Assert.Equal((ToolApprovalEventType.ToolApprovalApproved, "corr-decide", At), (approved.Type, approved.CorrelationId, approved.OccurredAt));
        Assert.Equal(ToolApprovalEventType.ToolApprovalDenied, denied.Type);
        Assert.Equal("approver-console", denied.Approval.DecidedBy);
    }

    [Fact]
    public void Event_ForAnythingButAPersonsDecision_CannotBeBuilt()
    {
        var pending = Pending();
        var used = pending.Approve(At, "approver-console").Use(pending.Binding, At, SecurityEventId.New());

        Assert.Throws<ArgumentException>(() => new ToolApprovalEvent(pending, "corr", At));
        Assert.Throws<ArgumentException>(() => new ToolApprovalEvent(used, "corr", At));
        // Withdrawn because its decision could not be recorded: denied, but by nobody.
        Assert.Throws<ArgumentException>(() => new ToolApprovalEvent(pending.Revoke(At), "corr", At));
        Assert.Throws<ArgumentNullException>(() => new ToolApprovalEvent(null!, "corr", At));
        Assert.Throws<ArgumentException>(() => new ToolApprovalEvent(pending.Approve(At, "approver-console"), " ", At));
    }

    private static ToolApproval Pending()
    {
        var call = new ToolApprovalBinding(new AgentId("support-agent"), "support-runtime", new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read"), new string('a', 64), null);
        var verdict = new AgentActionAuthorization(AgentActionReason.HumanApprovalRequired, RiskLevel.High, new RecognisedAgentAction(call.Agent, call.Tool, call.Action, call.Capability));
        return ToolApproval.Request(SecurityEventId.New(), "corr-held", call, verdict, null, At, TimeSpan.FromMinutes(10));
    }
}
