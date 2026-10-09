using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Domain.Policy;

namespace AgentShield.Domain.SecurityEvents;

/// <summary>The stage of a tool gateway request an audit entry records.</summary>
/// <remarks>
/// <para>Every request goes through one of these paths, recorded in this order:</para>
/// <list type="bullet">
/// <item>Executed: Requested → Allowed → Started → Completed (or Failed when the tool fails).</item>
/// <item>Not authorised, or stopped by the gateway's own checks: Requested → Blocked or Reviewed → Rejected. A Reviewed
/// entry names the pending approval created for the held call, when the gateway could run it.</item>
/// <item>Executed after a person's approval: Requested → Allowed (with the boundary's Review and the approval used) →
/// Started → Completed.</item>
/// <item>Grant refused by the execution authority: Requested → Allowed → Started → Rejected.</item>
/// </list>
/// <para>Each stage is recorded before the next one starts, so a tool never runs unless its Allowed and Started entries
/// were recorded first.</para>
/// </remarks>
public enum ToolGatewayEventType
{
    /// <summary>A tool execution request arrived from an identified agent; nothing is decided yet.</summary>
    ToolAuthorizationRequested = 1,

    /// <summary>The action was allowed and an execution grant was issued.</summary>
    ToolAuthorizationAllowed = 2,

    /// <summary>The action was blocked: by the authorization boundary or by the gateway's own checks.</summary>
    ToolAuthorizationBlocked = 3,

    /// <summary>The action was held for review by the authorization boundary.</summary>
    ToolAuthorizationReviewed = 4,

    /// <summary>The grant is being presented to the execution authority, which runs the tool if it accepts it.</summary>
    ToolExecutionStarted = 5,

    /// <summary>The tool ran and returned a result.</summary>
    ToolExecutionCompleted = 6,

    /// <summary>The tool did not run: the action was not allowed, or the execution authority refused the grant.</summary>
    ToolExecutionRejected = 7,

    /// <summary>The tool was invoked but failed; no result was returned.</summary>
    ToolExecutionFailed = 8,
}

/// <summary>
/// One audit entry of a tool gateway request. A request's entries share its <see cref="Id"/> (the security event of the
/// request) and are created only by the transitions below, so an entry out of order (a completion without a start, a start
/// without an Allow) or one whose outcome disagrees with its decision cannot be built.
/// </summary>
/// <remarks>
/// <para>Holds metadata only: identifiers, the trusted agent, the authorization boundary's verdict (which carries only the
/// names AgentShield recognises), the outcome, the execution ID and fixed-vocabulary codes. Never the tool arguments, the
/// tool's result, a grant's signature or anything else the caller wrote.</para>
/// <para><see cref="Id"/> identifies the request's security event; <see cref="CorrelationId"/> traces the HTTP request;
/// <see cref="ExecutionId"/> identifies the execution its grant authorised. Three different things.</para>
/// </remarks>
public sealed record ToolGatewayEvent
{
    private ToolGatewayEvent(
        SecurityEventId id,
        string correlationId,
        DateTimeOffset occurredAt,
        ToolGatewayEventType type,
        AgentId agent,
        SecurityDecision? inputDecision,
        AgentActionAuthorization? authorization,
        ToolExecutionOutcome? outcome,
        Guid? executionId,
        ToolArgumentViolation? argumentViolation,
        ExecutionGrantRejection? grantRejection,
        TimeSpan elapsed,
        SecurityEventId? inputEventId,
        Guid? approvalId,
        InputContextRejection? inputContextRejection,
        ToolApprovalRejection? approvalRejection)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(elapsed, TimeSpan.Zero);

        Id = id;
        CorrelationId = correlationId;
        OccurredAt = occurredAt;
        Type = type;
        Agent = agent;
        InputDecision = inputDecision;
        Authorization = authorization;
        Outcome = outcome;
        ExecutionId = executionId;
        ArgumentViolation = argumentViolation;
        GrantRejection = grantRejection;
        Elapsed = elapsed;
        InputEventId = inputEventId;
        ApprovalId = approvalId;
        InputContextRejection = inputContextRejection;
        ApprovalRejection = approvalRejection;
    }

    /// <summary>The gateway request's security event, shared by all of its entries.</summary>
    public SecurityEventId Id { get; }

    public string CorrelationId { get; }

    public DateTimeOffset OccurredAt { get; }

    public ToolGatewayEventType Type { get; }

    /// <summary>The agent the gateway acted for, taken from the authenticated caller (always a configured agent).</summary>
    public AgentId Agent { get; }

    /// <summary>
    /// The input decision the gateway applied (it can only tighten the verdict): the server's record of the referenced input
    /// security event, or the caller's report, whichever is stricter; for a request presenting an approval, the decision the
    /// approved call was held under.
    /// </summary>
    public SecurityDecision? InputDecision { get; }

    /// <summary>The input security event the request referenced (server-created by the firewall), if any.</summary>
    public SecurityEventId? InputEventId { get; }

    /// <summary>
    /// The approval this entry concerns: on a Reviewed entry, the pending approval created for the held call; on an Allowed
    /// entry, the approved approval this request used; carried by the request's later entries.
    /// </summary>
    public Guid? ApprovalId { get; }

    /// <summary>Why the referenced input event could not be verified, when the outcome is <see cref="ToolExecutionOutcome.InputContextRejected"/>.</summary>
    public InputContextRejection? InputContextRejection { get; }

    /// <summary>Why the presented approval does not authorise the call, when the outcome is <see cref="ToolExecutionOutcome.ApprovalRejected"/>.</summary>
    public ToolApprovalRejection? ApprovalRejection { get; }

    /// <summary>The authorization boundary's verdict; <see langword="null"/> only for <see cref="ToolGatewayEventType.ToolAuthorizationRequested"/>.</summary>
    public AgentActionAuthorization? Authorization { get; }

    /// <summary>How the request ended, once that is known (blocked, reviewed and terminal entries).</summary>
    public ToolExecutionOutcome? Outcome { get; }

    /// <summary>The execution grant's ID, from the Allowed entry on; <see langword="null"/> when no grant was issued.</summary>
    public Guid? ExecutionId { get; }

    /// <summary>Which argument rule was broken, when the outcome is <see cref="ToolExecutionOutcome.ArgumentsRejected"/>.</summary>
    public ToolArgumentViolation? ArgumentViolation { get; }

    /// <summary>Why the grant was refused, when the outcome is <see cref="ToolExecutionOutcome.ExecutionAuthorizationRejected"/>.</summary>
    public ExecutionGrantRejection? GrantRejection { get; }

    /// <summary>Time since the gateway started handling the request.</summary>
    public TimeSpan Elapsed { get; }

    /// <summary>The gateway's decision so far: <see langword="null"/> before the request was decided.</summary>
    public SecurityDecision? Decision => Type switch
    {
        ToolGatewayEventType.ToolAuthorizationRequested => null,
        ToolGatewayEventType.ToolAuthorizationAllowed or ToolGatewayEventType.ToolExecutionStarted => SecurityDecision.Allow,
        _ => ToolExecutionOutcomes.DecisionFor(Outcome!.Value),
    };

    /// <summary>Whether this is the request's last entry (Completed, Rejected or Failed).</summary>
    public bool IsTerminal => Type is ToolGatewayEventType.ToolExecutionCompleted
        or ToolGatewayEventType.ToolExecutionRejected
        or ToolGatewayEventType.ToolExecutionFailed;

    /// <summary>The first entry of a request: an identified agent asked to execute a tool action.</summary>
    public static ToolGatewayEvent Requested(
        SecurityEventId id,
        string correlationId,
        DateTimeOffset occurredAt,
        AgentId agent,
        SecurityDecision? inputDecision,
        SecurityEventId? inputEventId = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(correlationId);
        ArgumentNullException.ThrowIfNull(agent);

        if (inputEventId is { } input && input == default)
        {
            throw new ArgumentException("A referenced input security event requires an identifier.", nameof(inputEventId));
        }

        if (id == default)
        {
            throw new ArgumentException("A security event requires an identifier.", nameof(id));
        }

        if (inputDecision is { } decision && !Enum.IsDefined(decision))
        {
            throw new ArgumentOutOfRangeException(nameof(inputDecision), inputDecision, "Unknown security decision.");
        }

        return new ToolGatewayEvent(
            id, correlationId, occurredAt, ToolGatewayEventType.ToolAuthorizationRequested, agent, inputDecision,
            authorization: null, outcome: null, executionId: null, argumentViolation: null, grantRejection: null, TimeSpan.Zero, inputEventId, approvalId: null, inputContextRejection: null, approvalRejection: null);
    }

    /// <summary>
    /// The boundary allowed the action (or held it for review and a person approved exactly this call, <paramref name="approvalId"/>),
    /// the gateway's checks passed, and grant <paramref name="executionId"/> was issued.
    /// </summary>
    public ToolGatewayEvent Allowed(DateTimeOffset occurredAt, TimeSpan elapsed, AgentActionAuthorization authorization, Guid executionId, Guid? approvalId = null)
    {
        Expect(ToolGatewayEventType.ToolAuthorizationRequested);
        ArgumentNullException.ThrowIfNull(authorization);

        // A Review is never allowed on its own: only with the approval that lifted it. A Block is never allowed.
        var permitted = authorization.Decision switch
        {
            SecurityDecision.Allow => approvalId is null,
            SecurityDecision.Review => approvalId is { } approval && approval != Guid.Empty,
            _ => false,
        };
        if (!permitted)
        {
            throw new ArgumentException("Only an action the authorization boundary allowed, or a held action a person approved, can be allowed.", nameof(authorization));
        }

        if (executionId == Guid.Empty)
        {
            throw new ArgumentException("An allowed action requires the ID of its execution grant.", nameof(executionId));
        }

        return Next(ToolGatewayEventType.ToolAuthorizationAllowed, occurredAt, elapsed, authorization, outcome: null, executionId, argumentViolation: null, grantRejection: null, approvalId);
    }

    /// <summary>
    /// The action will not run: the boundary blocked it or held it for review, the referenced input security event could not
    /// be verified, the presented approval does not authorise this call, or the gateway's own checks (an executable tool, the
    /// argument policy) blocked what the boundary allowed or a person approved.
    /// </summary>
    /// <param name="approvalId">The approval the refusal concerns: for a held call, the pending approval created for it (if
    /// the gateway could run it); for a rejected approval, the one presented; for a check that blocked an approved call, the
    /// approval it used. Never anything else.</param>
    public ToolGatewayEvent Refused(
        DateTimeOffset occurredAt,
        TimeSpan elapsed,
        AgentActionAuthorization authorization,
        ToolExecutionOutcome outcome,
        ToolArgumentViolation? argumentViolation = null,
        Guid? approvalId = null,
        InputContextRejection? inputContextRejection = null,
        ToolApprovalRejection? approvalRejection = null)
    {
        Expect(ToolGatewayEventType.ToolAuthorizationRequested);
        ArgumentNullException.ThrowIfNull(authorization);

        // Which verdicts of the boundary each refusal can stand for: the boundary's own Block or Review; an unverifiable input
        // event, which blocks whatever the boundary said; a rejected approval, presented only for a Review; or one of the
        // gateway's checks, which run only on an Allow or an approved Review and can only turn it into a Block.
        var decision = authorization.Decision;
        var approved = approvalId is { } approval && approval != Guid.Empty;
        if (approvalId is { } empty && empty == Guid.Empty)
        {
            throw new ArgumentException("An approval requires an identifier.", nameof(approvalId));
        }

        var agrees = outcome switch
        {
            ToolExecutionOutcome.HeldForReview => decision == SecurityDecision.Review,
            ToolExecutionOutcome.ApprovalRejected => decision == SecurityDecision.Review && approved,
            ToolExecutionOutcome.Denied => decision == SecurityDecision.Block && !approved,
            ToolExecutionOutcome.InputContextRejected => !approved,
            ToolExecutionOutcome.ArgumentsRejected or ToolExecutionOutcome.ToolUnavailable =>
                (decision == SecurityDecision.Allow && !approved) || (decision == SecurityDecision.Review && approved),
            _ => throw new ArgumentOutOfRangeException(nameof(outcome), outcome, "Not an outcome of a refused action."),
        };

        if (!agrees)
        {
            throw new ArgumentException("The outcome disagrees with the authorization boundary's decision or the approval.", nameof(outcome));
        }

        if ((outcome == ToolExecutionOutcome.ArgumentsRejected) != (argumentViolation is not null)
            || (argumentViolation is { } violation && !Enum.IsDefined(violation)))
        {
            throw new ArgumentException("An argument violation is recorded exactly when the arguments were rejected.", nameof(argumentViolation));
        }

        if ((outcome == ToolExecutionOutcome.InputContextRejected) != (inputContextRejection is not null)
            || (inputContextRejection is { } inputRejection && !Enum.IsDefined(inputRejection)))
        {
            throw new ArgumentException("An input context rejection is recorded exactly when the input event was rejected.", nameof(inputContextRejection));
        }

        if ((outcome == ToolExecutionOutcome.ApprovalRejected) != (approvalRejection is not null)
            || (approvalRejection is { } rejectedApproval && !Enum.IsDefined(rejectedApproval)))
        {
            throw new ArgumentException("An approval rejection is recorded exactly when the presented approval was rejected.", nameof(approvalRejection));
        }

        var type = ToolExecutionOutcomes.DecisionFor(outcome) == SecurityDecision.Review
            ? ToolGatewayEventType.ToolAuthorizationReviewed
            : ToolGatewayEventType.ToolAuthorizationBlocked;

        return new ToolGatewayEvent(
            Id, CorrelationId, occurredAt, type, Agent, InputDecision, authorization, outcome, executionId: null, argumentViolation,
            grantRejection: null, elapsed, InputEventId, approvalId, inputContextRejection, approvalRejection);
    }

    /// <summary>The refused action is not executed: the request's last entry.</summary>
    public ToolGatewayEvent Rejected(DateTimeOffset occurredAt, TimeSpan elapsed)
    {
        Expect(ToolGatewayEventType.ToolAuthorizationBlocked, ToolGatewayEventType.ToolAuthorizationReviewed);
        return Next(ToolGatewayEventType.ToolExecutionRejected, occurredAt, elapsed, Authorization, Outcome, ExecutionId, ArgumentViolation, grantRejection: null, ApprovalId);
    }

    /// <summary>The grant is being presented to the execution authority.</summary>
    public ToolGatewayEvent Started(DateTimeOffset occurredAt, TimeSpan elapsed)
    {
        Expect(ToolGatewayEventType.ToolAuthorizationAllowed);
        return Next(ToolGatewayEventType.ToolExecutionStarted, occurredAt, elapsed, Authorization, outcome: null, ExecutionId, argumentViolation: null, grantRejection: null, ApprovalId);
    }

    /// <summary>The tool ran and returned a result: the request's last entry.</summary>
    public ToolGatewayEvent Completed(DateTimeOffset occurredAt, TimeSpan elapsed)
    {
        Expect(ToolGatewayEventType.ToolExecutionStarted);
        return Next(ToolGatewayEventType.ToolExecutionCompleted, occurredAt, elapsed, Authorization, ToolExecutionOutcome.Executed, ExecutionId, argumentViolation: null, grantRejection: null, ApprovalId);
    }

    /// <summary>The execution authority refused the grant, so the tool did not run: the request's last entry.</summary>
    public ToolGatewayEvent GrantRefused(DateTimeOffset occurredAt, TimeSpan elapsed, ExecutionGrantRejection rejection)
    {
        Expect(ToolGatewayEventType.ToolExecutionStarted);
        if (!Enum.IsDefined(rejection))
        {
            throw new ArgumentOutOfRangeException(nameof(rejection), rejection, "Unknown grant rejection.");
        }

        return Next(ToolGatewayEventType.ToolExecutionRejected, occurredAt, elapsed, Authorization, ToolExecutionOutcome.ExecutionAuthorizationRejected, ExecutionId, argumentViolation: null, rejection, ApprovalId);
    }

    /// <summary>The tool was invoked but failed: the request's last entry.</summary>
    public ToolGatewayEvent Failed(DateTimeOffset occurredAt, TimeSpan elapsed)
    {
        Expect(ToolGatewayEventType.ToolExecutionStarted);
        return Next(ToolGatewayEventType.ToolExecutionFailed, occurredAt, elapsed, Authorization, ToolExecutionOutcome.ExecutionFailed, ExecutionId, argumentViolation: null, grantRejection: null, ApprovalId);
    }

    private void Expect(params ToolGatewayEventType[] allowed)
    {
        if (!allowed.Contains(Type))
        {
            throw new InvalidOperationException($"A tool gateway request cannot move on from {Type} this way.");
        }
    }

    private ToolGatewayEvent Next(
        ToolGatewayEventType type,
        DateTimeOffset occurredAt,
        TimeSpan elapsed,
        AgentActionAuthorization? authorization,
        ToolExecutionOutcome? outcome,
        Guid? executionId,
        ToolArgumentViolation? argumentViolation,
        ExecutionGrantRejection? grantRejection,
        Guid? approvalId) =>
        new(Id, CorrelationId, occurredAt, type, Agent, InputDecision, authorization, outcome, executionId, argumentViolation, grantRejection, elapsed, InputEventId, approvalId, InputContextRejection, ApprovalRejection);
}
