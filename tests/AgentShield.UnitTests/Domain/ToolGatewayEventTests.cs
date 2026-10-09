using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.UnitTests.Domain;

/// <summary>
/// A tool gateway request's audit entries form a fixed lifecycle: no entry out of order (a start without an Allow, a completion
/// without a start), and no outcome that disagrees with the boundary's decision, can be built.
/// </summary>
public sealed class ToolGatewayEventTests
{
    private static readonly DateTimeOffset At = new(2026, 10, 7, 12, 0, 0, TimeSpan.Zero);
    private static readonly Guid ExecutionId = Guid.CreateVersion7();

    private static readonly AgentActionAuthorization Allow = Verdict(AgentActionReason.Permitted, RiskLevel.Low);
    private static readonly AgentActionAuthorization Review = Verdict(AgentActionReason.HumanApprovalRequired, RiskLevel.High);
    private static readonly AgentActionAuthorization Block = Verdict(AgentActionReason.CapabilityNotGranted, RiskLevel.Low);

    /// <summary>The transitions out of each stage that exist; every other one throws.</summary>
    private static readonly Dictionary<string, string[]> Allowed = new(StringComparer.Ordinal)
    {
        ["Requested"] = ["Allowed", "Refused"],
        ["Allowed"] = ["Started"],
        ["Blocked"] = ["Rejected"],
        ["Reviewed"] = ["Rejected"],
        ["Started"] = ["Completed", "GrantRefused", "Failed"],
        ["Completed"] = [],
        ["Rejected"] = [],
        ["GrantRejected"] = [],
        ["Failed"] = [],
    };

    [Fact]
    public void Requested_StartsTheLifecycle_Undecided()
    {
        var id = SecurityEventId.New();
        var requested = ToolGatewayEvent.Requested(id, "corr-gw", At, new AgentId("support-agent"), SecurityDecision.Review);

        Assert.Equal(ToolGatewayEventType.ToolAuthorizationRequested, requested.Type);
        Assert.Equal((id, "corr-gw", At, new AgentId("support-agent"), (SecurityDecision?)SecurityDecision.Review), (requested.Id, requested.CorrelationId, requested.OccurredAt, requested.Agent, requested.InputDecision));
        Assert.Null(requested.Decision);
        Assert.Null(requested.Authorization);
        Assert.Null(requested.Outcome);
        Assert.Null(requested.ExecutionId);
        Assert.False(requested.IsTerminal);
        Assert.Equal(TimeSpan.Zero, requested.Elapsed);
    }

    [Fact]
    public void Requested_RejectsAMissingIdCorrelationOrAgent_AndAnUndefinedInputDecision()
    {
        var agent = new AgentId("support-agent");
        Assert.Throws<ArgumentException>(() => ToolGatewayEvent.Requested(default, "corr", At, agent, null));
        Assert.Throws<ArgumentException>(() => ToolGatewayEvent.Requested(SecurityEventId.New(), " ", At, agent, null));
        Assert.Throws<ArgumentNullException>(() => ToolGatewayEvent.Requested(SecurityEventId.New(), "corr", At, null!, null));
        Assert.Throws<ArgumentOutOfRangeException>(() => ToolGatewayEvent.Requested(SecurityEventId.New(), "corr", At, agent, (SecurityDecision)9));
    }

    [Fact]
    public void Executed_RequestedAllowedStartedCompleted_SharesTheIdAndExecution_AndIsAllowOnlyAfterTheBoundaryAllowed()
    {
        var requested = Requested();
        var allowed = requested.Allowed(At, Ms(1), Allow, ExecutionId);
        var started = allowed.Started(At, Ms(2));
        var completed = started.Completed(At, Ms(3));

        Assert.Equal(
            [ToolGatewayEventType.ToolAuthorizationRequested, ToolGatewayEventType.ToolAuthorizationAllowed, ToolGatewayEventType.ToolExecutionStarted, ToolGatewayEventType.ToolExecutionCompleted],
            [requested.Type, allowed.Type, started.Type, completed.Type]);
        Assert.All(new[] { allowed, started, completed }, entry => Assert.Equal((requested.Id, requested.CorrelationId, requested.Agent, (Guid?)ExecutionId), (entry.Id, entry.CorrelationId, entry.Agent, entry.ExecutionId)));
        Assert.All(new[] { allowed, started, completed }, entry => Assert.Equal(SecurityDecision.Allow, entry.Decision));
        Assert.Equal(ToolExecutionOutcome.Executed, completed.Outcome);
        Assert.Null(allowed.Outcome);
        Assert.Null(started.Outcome);
        Assert.True(completed.IsTerminal);
        Assert.False(started.IsTerminal);
        Assert.Equal(Ms(3), completed.Elapsed);
    }

    [Fact]
    public void Allowed_RequiresTheBoundarysAllow_AndAGrant()
    {
        Assert.Throws<ArgumentException>(() => Requested().Allowed(At, Ms(1), Review, ExecutionId));
        Assert.Throws<ArgumentException>(() => Requested().Allowed(At, Ms(1), Block, ExecutionId));
        Assert.Throws<ArgumentException>(() => Requested().Allowed(At, Ms(1), Allow, Guid.Empty));
        Assert.Throws<ArgumentNullException>(() => Requested().Allowed(At, Ms(1), null!, ExecutionId));
    }

    [Fact]
    public void Allowed_AReview_OnlyWithTheApprovalThatLiftedIt_AndNeverABlock()
    {
        var approvalId = Guid.NewGuid();

        var approved = Requested().Allowed(At, Ms(1), Review, ExecutionId, approvalId);

        Assert.Equal((SecurityDecision.Allow, approvalId, SecurityDecision.Review), (approved.Decision, approved.ApprovalId, approved.Authorization!.Decision));
        Assert.Equal(approvalId, approved.Started(At, Ms(2)).Completed(At, Ms(3)).ApprovalId);
        Assert.Throws<ArgumentException>(() => Requested().Allowed(At, Ms(1), Review, ExecutionId));
        Assert.Throws<ArgumentException>(() => Requested().Allowed(At, Ms(1), Review, ExecutionId, Guid.Empty));
        Assert.Throws<ArgumentException>(() => Requested().Allowed(At, Ms(1), Block, ExecutionId, approvalId));
        Assert.Throws<ArgumentException>(() => Requested().Allowed(At, Ms(1), Allow, ExecutionId, approvalId));
    }

    [Fact]
    public void Requested_KeepsTheReferencedInputEvent_ThroughEveryLaterEntry()
    {
        var input = SecurityEventId.New();

        var requested = ToolGatewayEvent.Requested(SecurityEventId.New(), "corr-gw", At, new AgentId("support-agent"), SecurityDecision.Review, input);
        var rejected = requested.Refused(At, Ms(1), Review, ToolExecutionOutcome.HeldForReview).Rejected(At, Ms(2));

        Assert.Equal((input, input), (requested.InputEventId!.Value, rejected.InputEventId!.Value));
        Assert.Throws<ArgumentException>(() => ToolGatewayEvent.Requested(SecurityEventId.New(), "corr-gw", At, new AgentId("support-agent"), null, default(SecurityEventId)));
    }

    [Fact]
    public void Refused_EveryOutcomeAndVerdict_IsAcceptedOnlyWhereTheyAgree()
    {
        // Review and Block refusals repeat the boundary; an unverifiable input event blocks whatever the boundary said; a
        // rejected approval is presented only for a Review; the gateway's own checks run only on an Allow (without an approval)
        // or on a Review a person approved (with the approval used). Every outcome × verdict × approval presence is checked.
        static bool Valid(ToolExecutionOutcome outcome, SecurityDecision verdict, bool approval) => outcome switch
        {
            ToolExecutionOutcome.HeldForReview => verdict == SecurityDecision.Review,
            ToolExecutionOutcome.ApprovalRejected => verdict == SecurityDecision.Review && approval,
            ToolExecutionOutcome.Denied => verdict == SecurityDecision.Block && !approval,
            ToolExecutionOutcome.InputContextRejected => !approval,
            ToolExecutionOutcome.ArgumentsRejected or ToolExecutionOutcome.ToolUnavailable =>
                (verdict == SecurityDecision.Allow && !approval) || (verdict == SecurityDecision.Review && approval),
            _ => false,
        };

        var refusals = new HashSet<ToolExecutionOutcome>
        {
            ToolExecutionOutcome.HeldForReview, ToolExecutionOutcome.ApprovalRejected, ToolExecutionOutcome.Denied,
            ToolExecutionOutcome.InputContextRejected, ToolExecutionOutcome.ArgumentsRejected, ToolExecutionOutcome.ToolUnavailable,
        };
        var approvalId = Guid.NewGuid();
        var checkedCombinations = 0;
        foreach (var outcome in Enum.GetValues<ToolExecutionOutcome>())
        {
            foreach (var verdict in new[] { Allow, Review, Block })
            {
                foreach (var withApproval in new[] { false, true })
                {
                    var violation = outcome == ToolExecutionOutcome.ArgumentsRejected ? ToolArgumentViolation.TooLong : (ToolArgumentViolation?)null;
                    var inputRejection = outcome == ToolExecutionOutcome.InputContextRejected ? InputContextRejection.OtherTrace : (InputContextRejection?)null;
                    var approvalRejection = outcome == ToolExecutionOutcome.ApprovalRejected ? ToolApprovalRejection.WrongTool : (ToolApprovalRejection?)null;
                    var approval = withApproval ? approvalId : (Guid?)null;
                    ToolGatewayEvent Refuse() => Requested().Refused(At, Ms(1), verdict, outcome, violation, approval, inputRejection, approvalRejection);

                    if (Valid(outcome, verdict.Decision, withApproval))
                    {
                        var refused = Refuse();
                        Assert.Equal(outcome, refused.Outcome);
                        Assert.Equal(ToolExecutionOutcomes.DecisionFor(outcome), refused.Decision);
                        Assert.Equal(refused.Decision == SecurityDecision.Review ? ToolGatewayEventType.ToolAuthorizationReviewed : ToolGatewayEventType.ToolAuthorizationBlocked, refused.Type);
                        Assert.Null(refused.ExecutionId);
                        Assert.Equal(approval, refused.ApprovalId);
                        Assert.Equal((inputRejection, approvalRejection), (refused.InputContextRejection, refused.ApprovalRejection));
                    }
                    else if (refusals.Contains(outcome))
                    {
                        Assert.Throws<ArgumentException>(Refuse);
                    }
                    else
                    {
                        // Executed, ExecutionFailed and ExecutionAuthorizationRejected are no refusal at all, whatever the verdict.
                        Assert.Throws<ArgumentOutOfRangeException>(Refuse);
                    }

                    checkedCombinations++;
                }
            }
        }

        Assert.Equal(9 * 3 * 2, checkedCombinations);
    }

    [Fact]
    public void Refused_WithoutTheBoundarysVerdict_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Requested().Refused(At, Ms(1), null!, ToolExecutionOutcome.Denied));
    }

    [Fact]
    public void Refused_AnArgumentViolationIsRecorded_ExactlyWhenTheArgumentsWereRejected()
    {
        Assert.Equal(ToolArgumentViolation.UnexpectedArgument, Requested().Refused(At, Ms(1), Allow, ToolExecutionOutcome.ArgumentsRejected, ToolArgumentViolation.UnexpectedArgument).ArgumentViolation);
        Assert.Throws<ArgumentException>(() => Requested().Refused(At, Ms(1), Allow, ToolExecutionOutcome.ArgumentsRejected));
        Assert.Throws<ArgumentException>(() => Requested().Refused(At, Ms(1), Allow, ToolExecutionOutcome.ToolUnavailable, ToolArgumentViolation.Empty));
        Assert.Throws<ArgumentException>(() => Requested().Refused(At, Ms(1), Block, ToolExecutionOutcome.Denied, ToolArgumentViolation.Empty));
        Assert.Throws<ArgumentException>(() => Requested().Refused(At, Ms(1), Allow, ToolExecutionOutcome.ArgumentsRejected, (ToolArgumentViolation)77));
    }

    [Fact]
    public void Refused_EachRejectionCodeIsRecorded_ExactlyWithItsOwnOutcome_AndAnApprovalNeedsAnId()
    {
        var approval = Guid.NewGuid();

        Assert.Equal(InputContextRejection.OtherClient, Requested().Refused(At, Ms(1), Allow, ToolExecutionOutcome.InputContextRejected, inputContextRejection: InputContextRejection.OtherClient).InputContextRejection);
        Assert.Throws<ArgumentException>(() => Requested().Refused(At, Ms(1), Allow, ToolExecutionOutcome.InputContextRejected));
        Assert.Throws<ArgumentException>(() => Requested().Refused(At, Ms(1), Block, ToolExecutionOutcome.Denied, inputContextRejection: InputContextRejection.NotFound));
        Assert.Throws<ArgumentException>(() => Requested().Refused(At, Ms(1), Allow, ToolExecutionOutcome.InputContextRejected, inputContextRejection: (InputContextRejection)77));

        var rejected = Requested().Refused(At, Ms(1), Review, ToolExecutionOutcome.ApprovalRejected, approvalId: approval, approvalRejection: ToolApprovalRejection.Expired);
        Assert.Equal((ToolApprovalRejection.Expired, approval), (rejected.ApprovalRejection, rejected.ApprovalId));
        Assert.Throws<ArgumentException>(() => Requested().Refused(At, Ms(1), Review, ToolExecutionOutcome.ApprovalRejected, approvalId: approval));
        Assert.Throws<ArgumentException>(() => Requested().Refused(At, Ms(1), Review, ToolExecutionOutcome.HeldForReview, approvalRejection: ToolApprovalRejection.NotFound));
        Assert.Throws<ArgumentException>(() => Requested().Refused(At, Ms(1), Review, ToolExecutionOutcome.ApprovalRejected, approvalId: approval, approvalRejection: (ToolApprovalRejection)77));

        Assert.Throws<ArgumentException>(() => Requested().Refused(At, Ms(1), Review, ToolExecutionOutcome.HeldForReview, approvalId: Guid.Empty));
    }

    [Fact]
    public void Rejected_EndsARefusal_KeepingItsOutcome_WithoutAGrant()
    {
        var rejected = Requested().Refused(At, Ms(1), Allow, ToolExecutionOutcome.ArgumentsRejected, ToolArgumentViolation.WrongType).Rejected(At, Ms(2));

        Assert.Equal(ToolGatewayEventType.ToolExecutionRejected, rejected.Type);
        Assert.Equal((ToolExecutionOutcome.ArgumentsRejected, (ToolArgumentViolation?)ToolArgumentViolation.WrongType, (Guid?)null), (rejected.Outcome!.Value, rejected.ArgumentViolation, rejected.ExecutionId));
        Assert.Equal(SecurityDecision.Block, rejected.Decision);
        Assert.Same(Allow, rejected.Authorization);
        Assert.True(rejected.IsTerminal);
    }

    [Fact]
    public void GrantRefused_IsABlockWithTheRejection_AfterTheStart()
    {
        var rejected = Requested().Allowed(At, Ms(1), Allow, ExecutionId).Started(At, Ms(2)).GrantRefused(At, Ms(3), ExecutionGrantRejection.Expired);

        Assert.Equal(ToolGatewayEventType.ToolExecutionRejected, rejected.Type);
        Assert.Equal((ToolExecutionOutcome.ExecutionAuthorizationRejected, (ExecutionGrantRejection?)ExecutionGrantRejection.Expired, (Guid?)ExecutionId), (rejected.Outcome!.Value, rejected.GrantRejection, rejected.ExecutionId));
        Assert.Equal(SecurityDecision.Block, rejected.Decision);
        Assert.Throws<ArgumentOutOfRangeException>(() => Requested().Allowed(At, Ms(1), Allow, ExecutionId).Started(At, Ms(2)).GrantRefused(At, Ms(3), (ExecutionGrantRejection)0));
    }

    [Fact]
    public void Failed_IsAnInvokedTool_ThatReturnedNothing()
    {
        var failed = Requested().Allowed(At, Ms(1), Allow, ExecutionId).Started(At, Ms(2)).Failed(At, Ms(3));

        Assert.Equal((ToolGatewayEventType.ToolExecutionFailed, (ToolExecutionOutcome?)ToolExecutionOutcome.ExecutionFailed), (failed.Type, failed.Outcome));
        Assert.Equal(SecurityDecision.Allow, failed.Decision);
        Assert.True(failed.IsTerminal);
    }

    [Fact]
    public void EveryTransitionFromEveryStage_IsPossibleOnlyWhereTheLifecycleAllowsIt()
    {
        var checkedTransitions = 0;
        foreach (var (stage, entry) in Stages())
        {
            foreach (var (transition, apply) in Transitions())
            {
                if (Allowed[stage].Contains(transition))
                {
                    Assert.NotNull(apply(entry));
                }
                else
                {
                    Assert.Throws<InvalidOperationException>(() => apply(entry));
                }

                checkedTransitions++;
            }
        }

        Assert.Equal(Allowed.Count * 7, checkedTransitions);
    }

    [Fact]
    public void Elapsed_CannotBeNegative()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => Requested().Allowed(At, TimeSpan.FromTicks(-1), Allow, ExecutionId));
    }

    private static IEnumerable<(string Stage, ToolGatewayEvent Entry)> Stages()
    {
        var requested = Requested();
        var allowed = requested.Allowed(At, Ms(1), Allow, ExecutionId);
        var started = allowed.Started(At, Ms(2));
        var blocked = requested.Refused(At, Ms(1), Block, ToolExecutionOutcome.Denied);
        yield return ("Requested", requested);
        yield return ("Allowed", allowed);
        yield return ("Blocked", blocked);
        yield return ("Reviewed", requested.Refused(At, Ms(1), Review, ToolExecutionOutcome.HeldForReview));
        yield return ("Started", started);
        yield return ("Completed", started.Completed(At, Ms(3)));
        yield return ("Rejected", blocked.Rejected(At, Ms(2)));
        yield return ("GrantRejected", started.GrantRefused(At, Ms(3), ExecutionGrantRejection.AlreadyUsed));
        yield return ("Failed", started.Failed(At, Ms(3)));
    }

    private static IEnumerable<(string Name, Func<ToolGatewayEvent, ToolGatewayEvent> Apply)> Transitions()
    {
        yield return ("Allowed", entry => entry.Allowed(At, Ms(5), Allow, ExecutionId));
        yield return ("Refused", entry => entry.Refused(At, Ms(5), Block, ToolExecutionOutcome.Denied));
        yield return ("Rejected", entry => entry.Rejected(At, Ms(5)));
        yield return ("Started", entry => entry.Started(At, Ms(5)));
        yield return ("Completed", entry => entry.Completed(At, Ms(5)));
        yield return ("GrantRefused", entry => entry.GrantRefused(At, Ms(5), ExecutionGrantRejection.WrongTool));
        yield return ("Failed", entry => entry.Failed(At, Ms(5)));
    }

    private static ToolGatewayEvent Requested() =>
        ToolGatewayEvent.Requested(SecurityEventId.New(), "corr-gw", At, new AgentId("support-agent"), inputDecision: null);

    private static TimeSpan Ms(int milliseconds) => TimeSpan.FromMilliseconds(milliseconds);

    private static AgentActionAuthorization Verdict(AgentActionReason reason, RiskLevel risk) =>
        new(reason, risk, new RecognisedAgentAction(new AgentId("support-agent"), new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read")));
}
