using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;

namespace AgentShield.Application.Agents.Approvals;

/// <summary>
/// A held tool call's approval as the approval endpoints return it: metadata only. Never the arguments or their digest (a
/// digest of a short argument could be guessed back), never the input, a credential, or who the clients are.
/// </summary>
/// <param name="ApprovalId">The approval's random identifier.</param>
/// <param name="Status">Its status now: an approval past its expiry is <c>Expired</c> whatever it was.</param>
/// <param name="SecurityEventId">The security event of the gateway request that was held.</param>
/// <param name="CorrelationId">The trace of that request.</param>
/// <param name="AgentId">The agent (always a configured agent: taken from its credential).</param>
/// <param name="Tool">The tool (a catalogued name).</param>
/// <param name="Action">The tool action (a catalogued name).</param>
/// <param name="Capability">The capability the action requires.</param>
/// <param name="RiskLevel">Risk of the action itself.</param>
/// <param name="Reason">Why the authorization boundary held it: a high-risk action, or an input held for review.</param>
/// <param name="InputDecision">The input decision the call was held under, when it had one.</param>
/// <param name="RequestedAt">When the gateway held the call.</param>
/// <param name="ExpiresAt">Until when it can be decided and, once approved, used.</param>
/// <param name="DecidedAt">When a person decided it, if one did.</param>
public sealed record ToolApprovalResponse(
    Guid ApprovalId,
    ToolApprovalStatus Status,
    Guid SecurityEventId,
    string CorrelationId,
    string AgentId,
    string Tool,
    string Action,
    string Capability,
    RiskLevel RiskLevel,
    AgentActionReason Reason,
    SecurityDecision? InputDecision,
    DateTimeOffset RequestedAt,
    DateTimeOffset ExpiresAt,
    DateTimeOffset? DecidedAt)
{
    /// <summary>The response for <paramref name="approval"/> as it stands at <paramref name="now"/>.</summary>
    public static ToolApprovalResponse From(ToolApproval approval, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(approval);

        var binding = approval.Binding;
        return new ToolApprovalResponse(
            approval.Id,
            approval.StatusAt(now),
            approval.RequestEventId.Value,
            approval.CorrelationId,
            binding.Agent.Value,
            binding.Tool.Value,
            binding.Action.Value,
            binding.Capability.Value,
            approval.Risk,
            approval.Reason,
            approval.InputDecision,
            approval.RequestedAt,
            approval.ExpiresAt,
            approval.DecidedAt);
    }
}

/// <summary>The most recent approvals, newest first.</summary>
public sealed record ToolApprovalListResponse(IReadOnlyList<ToolApprovalResponse> Items);
