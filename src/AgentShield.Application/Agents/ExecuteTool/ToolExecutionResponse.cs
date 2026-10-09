using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;

namespace AgentShield.Application.Agents.ExecuteTool;

/// <summary>
/// What the tool gateway did with an execution request: its decision, whether the tool ran, and the tool's result if it did.
/// </summary>
/// <remarks>
/// Never echoes the request (not the arguments, not a made-up name), never names a policy rule, catalogue entry, grant or
/// argument rule, and never carries a credential: the execution ID is an audit identifier and authorises nothing.
/// </remarks>
/// <param name="SecurityEventId">The gateway request's security event (its audit entries carry the same ID).</param>
/// <param name="Decision">Allow only when the tool ran; Review or Block otherwise.</param>
/// <param name="Executed">Whether the tool ran.</param>
/// <param name="Outcome">How the request ended (which stage stopped it, if any).</param>
/// <param name="AuthorizationReason">The authorization boundary's reason for its verdict on the action.</param>
/// <param name="RiskLevel">Risk of the action itself (Low to Critical; Critical when the action is unknown).</param>
/// <param name="ExecutionId">The execution grant's ID when one was issued; <c>null</c> otherwise.</param>
/// <param name="Result">The tool's result when it ran; <c>null</c> otherwise.</param>
/// <param name="ApprovalId">For a held call the gateway can run, the pending approval created for it (a person decides it;
/// the agent then presents it with the same call); for a call that ran after approval, the approval it used; for a rejected
/// approval, the one presented. <c>null</c> otherwise.</param>
public sealed record ToolExecutionResponse(
    Guid SecurityEventId,
    SecurityDecision Decision,
    bool Executed,
    ToolExecutionOutcome Outcome,
    AgentActionReason AuthorizationReason,
    RiskLevel RiskLevel,
    Guid? ExecutionId,
    ToolResultResponse? Result,
    Guid? ApprovalId = null);

/// <summary>A tool's result.</summary>
/// <param name="Found">Whether the tool found (or produced) a result.</param>
/// <param name="Text">The result text, at most 2,000 characters; <c>null</c> when nothing was found. For the reference tool
/// it comes from its own fixed dataset, never from the request.</param>
public sealed record ToolResultResponse(bool Found, string? Text);
