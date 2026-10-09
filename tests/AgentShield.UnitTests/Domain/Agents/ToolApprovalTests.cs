using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.UnitTests.Domain.Agents;

/// <summary>
/// A person's approval of a held tool call (Milestone 13): created only for a Review, decided once, used once for exactly the
/// call it binds, and worthless after its expiry, a denial or its use. Metadata only.
/// </summary>
public sealed class ToolApprovalTests
{
    private static readonly DateTimeOffset At = new(2026, 10, 7, 12, 0, 0, TimeSpan.Zero);
    private static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);
    private static readonly string Digest = new('a', 64);

    private static readonly AgentActionAuthorization HighRisk = Verdict(AgentActionReason.HumanApprovalRequired, RiskLevel.High);

    [Fact]
    public void Request_AHeldCall_IsPending_BoundToTheCall_WithTheBoundarysRiskAndReason_UntilItsExpiry()
    {
        var binding = Binding();
        var requestEvent = SecurityEventId.New();

        var approval = ToolApproval.Request(requestEvent, "corr-held", binding, HighRisk, SecurityDecision.Review, At, Lifetime);

        Assert.Equal(ToolApprovalStatus.Pending, approval.Status);
        Assert.Equal((requestEvent, "corr-held", binding), (approval.RequestEventId, approval.CorrelationId, approval.Binding));
        Assert.Equal((RiskLevel.High, AgentActionReason.HumanApprovalRequired, SecurityDecision.Review), (approval.Risk, approval.Reason, approval.InputDecision));
        Assert.Equal((At, At + Lifetime), (approval.RequestedAt, approval.ExpiresAt));
        Assert.Equal(4, approval.Id.Version);
        Assert.Null(approval.DecidedBy);
        Assert.Null(approval.UsedBy);
    }

    [Theory]
    [InlineData(AgentActionReason.Permitted, RiskLevel.Low)]
    [InlineData(AgentActionReason.CapabilityNotGranted, RiskLevel.High)]
    [InlineData(AgentActionReason.CriticalActionDenied, RiskLevel.Critical)]
    [InlineData(AgentActionReason.InputBlocked, RiskLevel.Low)]
    public void Request_AnythingButAReview_CannotBeApproved(AgentActionReason reason, RiskLevel risk)
    {
        Assert.Throws<ArgumentException>(() => ToolApproval.Request(SecurityEventId.New(), "corr", Binding(), Verdict(reason, risk), null, At, Lifetime));
    }

    [Fact]
    public void Request_RequiresARequestEventAPositiveLifetimeAndAKnownInputDecision()
    {
        Assert.Throws<ArgumentException>(() => ToolApproval.Request(default, "corr", Binding(), HighRisk, null, At, Lifetime));
        Assert.Throws<ArgumentOutOfRangeException>(() => ToolApproval.Request(SecurityEventId.New(), "corr", Binding(), HighRisk, null, At, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => ToolApproval.Request(SecurityEventId.New(), "corr", Binding(), HighRisk, (SecurityDecision)99, At, Lifetime));
        Assert.Throws<ArgumentException>(() => ToolApproval.Request(SecurityEventId.New(), " ", Binding(), HighRisk, null, At, Lifetime));
    }

    [Fact]
    public void Decide_APendingApproval_IsDecidedOnce_ByTheNamedClient()
    {
        var pending = Pending();

        var approved = pending.Approve(At.AddMinutes(1), "approver-console");
        var denied = pending.Deny(At.AddMinutes(1), "approver-console");

        Assert.Equal((ToolApprovalStatus.Approved, "approver-console", At.AddMinutes(1)), (approved.Status, approved.DecidedBy, approved.DecidedAt));
        Assert.Equal(ToolApprovalStatus.Denied, denied.Status);
        Assert.Throws<InvalidOperationException>(() => approved.Approve(At.AddMinutes(2), "approver-console"));
        Assert.Throws<InvalidOperationException>(() => approved.Deny(At.AddMinutes(2), "approver-console"));
        Assert.Throws<InvalidOperationException>(() => denied.Approve(At.AddMinutes(2), "approver-console"));
        Assert.Throws<ArgumentException>(() => pending.Approve(At, " "));
    }

    [Fact]
    public void Expiry_APendingOrApprovedApproval_IsExpiredAtItsExpiry_AndCanNoLongerBeDecidedOrUsed()
    {
        var pending = Pending();
        var approved = pending.Approve(At.AddMinutes(1), "approver");
        var expiry = pending.ExpiresAt;

        Assert.Equal(ToolApprovalStatus.Pending, pending.StatusAt(expiry.AddTicks(-1)));
        Assert.Equal(ToolApprovalStatus.Expired, pending.StatusAt(expiry));
        Assert.Equal(ToolApprovalStatus.Approved, approved.StatusAt(expiry.AddTicks(-1)));
        Assert.Equal(ToolApprovalStatus.Expired, approved.StatusAt(expiry));
        Assert.Throws<InvalidOperationException>(() => pending.Approve(expiry, "approver"));
        Assert.Equal(ToolApprovalRejection.Expired, approved.RejectionFor(Binding(), expiry));
        Assert.Throws<InvalidOperationException>(() => approved.Use(Binding(), expiry, SecurityEventId.New()));
        Assert.Equal(ToolApprovalStatus.Denied, pending.Deny(At, "approver").StatusAt(expiry.AddDays(1)));
    }

    [Fact]
    public void Use_AnApprovedApproval_AuthorisesExactlyItsCall_Once()
    {
        var approved = Pending().Approve(At.AddMinutes(1), "approver");
        var user = SecurityEventId.New();

        Assert.Null(approved.RejectionFor(Binding(), At.AddMinutes(2)));
        var used = approved.Use(Binding(), At.AddMinutes(2), user);

        Assert.Equal((ToolApprovalStatus.Used, user, At.AddMinutes(2)), (used.Status, used.UsedBy, used.UsedAt));
        Assert.Equal(ToolApprovalRejection.AlreadyUsed, used.RejectionFor(Binding(), At.AddMinutes(3)));
        Assert.Equal(ToolApprovalRejection.AlreadyUsed, used.RejectionFor(Binding(), used.ExpiresAt.AddDays(1)));
        Assert.Throws<InvalidOperationException>(() => used.Use(Binding(), At.AddMinutes(3), SecurityEventId.New()));
        Assert.Throws<ArgumentException>(() => Pending().Approve(At, "approver").Use(Binding(), At, default));
    }

    [Fact]
    public void Use_APendingOrDeniedApproval_AuthorisesNothing()
    {
        Assert.Equal(ToolApprovalRejection.NotApproved, Pending().RejectionFor(Binding(), At));
        Assert.Equal(ToolApprovalRejection.NotApproved, Pending().Deny(At, "approver").RejectionFor(Binding(), At));
        Assert.Throws<InvalidOperationException>(() => Pending().Use(Binding(), At, SecurityEventId.New()));
    }

    public static TheoryData<string, ToolApprovalRejection> OtherCalls => new()
    {
        { "agent", ToolApprovalRejection.WrongAgent },
        { "client", ToolApprovalRejection.WrongClient },
        { "tool", ToolApprovalRejection.WrongTool },
        { "action", ToolApprovalRejection.WrongAction },
        { "capability", ToolApprovalRejection.WrongCapability },
        { "arguments", ToolApprovalRejection.WrongArguments },
        { "input", ToolApprovalRejection.WrongInputEvent },
    };

    [Theory]
    [MemberData(nameof(OtherCalls))]
    public void Use_AnApprovalForOneCall_NeverAuthorisesAnother(string differs, ToolApprovalRejection expected)
    {
        var input = SecurityEventId.New();
        var approved = ToolApproval.Request(SecurityEventId.New(), "corr", Binding(input: input), HighRisk, null, At, Lifetime).Approve(At, "approver");
        var other = differs switch
        {
            "agent" => Binding(agent: "other-agent", input: input),
            "client" => Binding(client: "other-runtime", input: input),
            "tool" => Binding(tool: "email", input: input),
            "action" => Binding(action: "search", input: input),
            "capability" => Binding(capability: "knowledge:write", input: input),
            "arguments" => Binding(digest: new string('b', 64), input: input),
            _ => Binding(input: SecurityEventId.New()),
        };

        Assert.Equal(expected, approved.RejectionFor(other, At.AddMinutes(1)));
        Assert.Throws<InvalidOperationException>(() => approved.Use(other, At.AddMinutes(1), SecurityEventId.New()));
        Assert.Null(approved.RejectionFor(Binding(input: input), At.AddMinutes(1)));
    }

    [Fact]
    public void Use_ACallPresentedWithoutItsInputEvent_IsStillTheBoundCall()
    {
        // The approval carries the input event the call was held under; presenting the call without repeating it changes nothing.
        var approved = ToolApproval.Request(SecurityEventId.New(), "corr", Binding(input: SecurityEventId.New()), HighRisk, SecurityDecision.Review, At, Lifetime).Approve(At, "approver");

        Assert.Null(approved.RejectionFor(Binding(input: null), At));
    }

    [Fact]
    public void Revoke_WithdrawsPendingAndApprovedApprovals_AndLeavesFinishedOnesAsTheyAre()
    {
        var used = Pending().Approve(At, "approver").Use(Binding(), At, SecurityEventId.New());

        Assert.Equal(ToolApprovalStatus.Denied, Pending().Revoke(At).Status);
        Assert.Equal(ToolApprovalStatus.Denied, Pending().Approve(At, "approver").Revoke(At).Status);
        Assert.Equal(ToolApprovalStatus.Used, used.Revoke(At).Status);
        Assert.Equal(ToolApprovalRejection.NotApproved, Pending().Approve(At, "approver").Revoke(At).RejectionFor(Binding(), At));
    }

    [Theory]
    [InlineData("")]
    [InlineData("abc")]
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")]
    [InlineData("gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg")]
    public void Binding_KeepsOnlyAWellFormedDigestOfTheArguments(string digest)
    {
        Assert.Throws<ArgumentException>(() => Binding(digest: digest));
    }

    public static TheoryData<string> DigestsWithOneBadCharacter => new()
    {
        "A" + new string('a', 63),
        new string('a', 63) + "g",
        new string('a', 32) + " " + new string('a', 31),
    };

    [Theory]
    [MemberData(nameof(DigestsWithOneBadCharacter))]
    public void Binding_RejectsADigestWithASingleBadCharacter(string digest)
    {
        Assert.Throws<ArgumentException>(() => Binding(digest: digest));
    }

    [Fact]
    public void Binding_RequiresEveryPartOfTheCall_AndARealInputEventWhenOneIsReferenced()
    {
        var (agent, tool, action, capability) = (new AgentId("support-agent"), new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read"));

        Assert.Throws<ArgumentNullException>(() => new ToolApprovalBinding(null!, "support-runtime", tool, action, capability, Digest, null));
        Assert.Throws<ArgumentNullException>(() => new ToolApprovalBinding(agent, "support-runtime", null!, action, capability, Digest, null));
        Assert.Throws<ArgumentNullException>(() => new ToolApprovalBinding(agent, "support-runtime", tool, null!, capability, Digest, null));
        Assert.Throws<ArgumentNullException>(() => new ToolApprovalBinding(agent, "support-runtime", tool, action, null!, Digest, null));
        Assert.Throws<ArgumentException>(() => new ToolApprovalBinding(agent, " ", tool, action, capability, Digest, null));
        Assert.Throws<ArgumentException>(() => Binding(input: default(SecurityEventId)));
        Assert.Throws<ArgumentNullException>(() => Binding().Mismatch(null!));
    }

    [Fact]
    public void Request_RequiresTheCallAndTheBoundarysVerdict()
    {
        Assert.Throws<ArgumentNullException>(() => ToolApproval.Request(SecurityEventId.New(), "corr", null!, HighRisk, null, At, Lifetime));
        Assert.Throws<ArgumentNullException>(() => ToolApproval.Request(SecurityEventId.New(), "corr", Binding(), null!, null, At, Lifetime));
    }

    [Fact]
    public void Binding_PrintsTheCall_ButNeitherTheDigestNorTheClient()
    {
        var text = Binding(digest: new string('c', 64)).ToString();

        Assert.Equal("ToolApprovalBinding { Agent = support-agent, Tool = knowledge, Action = lookup }", text);
        Assert.DoesNotContain("cccc", text, StringComparison.Ordinal);
        Assert.DoesNotContain("support-runtime", text, StringComparison.Ordinal);
    }

    private static ToolApproval Pending() => ToolApproval.Request(SecurityEventId.New(), "corr", Binding(), HighRisk, null, At, Lifetime);

    private static ToolApprovalBinding Binding(
        string agent = "support-agent",
        string client = "support-runtime",
        string tool = "knowledge",
        string action = "lookup",
        string capability = "knowledge:read",
        string? digest = null,
        SecurityEventId? input = null) =>
        new(new AgentId(agent), client, new ToolId(tool), new ActionName(action), new Capability(capability), digest ?? Digest, input);

    private static AgentActionAuthorization Verdict(AgentActionReason reason, RiskLevel risk) =>
        new(reason, risk, new RecognisedAgentAction(new AgentId("support-agent"), new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read")));
}
