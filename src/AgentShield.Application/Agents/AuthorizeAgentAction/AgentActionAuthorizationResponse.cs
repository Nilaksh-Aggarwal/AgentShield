using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;

namespace AgentShield.Application.Agents.AuthorizeAgentAction;

/// <summary>
/// The authorization decision on a proposed agent action. Only <see cref="SecurityDecision.Allow"/> permits executing the
/// action; Review means a person must approve it first, Block means it must not run.
/// </summary>
/// <remarks>Never echoes the request, and never names policy rules, the catalogue entry or the agent's grants.</remarks>
/// <param name="SecurityEventId">Identifier of the audit record of this decision (distinct from the correlation ID).</param>
/// <param name="Decision">Allow, Review or Block.</param>
/// <param name="RiskLevel">Risk of the action itself (Low to Critical); Critical when the action is unknown.</param>
/// <param name="Reason">Coarse reason code for the decision.</param>
public sealed record AgentActionAuthorizationResponse(
    Guid SecurityEventId,
    SecurityDecision Decision,
    RiskLevel RiskLevel,
    AgentActionReason Reason);
