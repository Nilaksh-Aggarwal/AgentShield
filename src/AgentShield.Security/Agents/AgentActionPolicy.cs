using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;

namespace AgentShield.Security.Agents;

/// <summary>
/// The agent action policy: ordered rules, evaluated top-down, the first that applies gives the reason (and with it the
/// decision, <see cref="AgentActionReasons.DecisionFor"/>). Changing the policy means changing these rules.
/// </summary>
/// <remarks>
/// <list type="number">
/// <item>Agent not configured → <see cref="AgentActionReason.UnknownAgent"/> (Block)</item>
/// <item>Caller not bound to the agent → <see cref="AgentActionReason.CallerNotBoundToAgent"/> (Block)</item>
/// <item>Tool not catalogued → <see cref="AgentActionReason.UnknownTool"/> (Block)</item>
/// <item>Action not catalogued → <see cref="AgentActionReason.UnknownAction"/> (Block)</item>
/// <item>Claimed capability is not the required one → <see cref="AgentActionReason.CapabilityMismatch"/> (Block)</item>
/// <item>Agent does not hold the required capability → <see cref="AgentActionReason.CapabilityNotGranted"/> (Block)</item>
/// <item>Risk at or above <see cref="DenyAt"/> → <see cref="AgentActionReason.CriticalActionDenied"/> (Block)</item>
/// <item>Input decision Block → <see cref="AgentActionReason.InputBlocked"/> (Block)</item>
/// <item>Risk at or above <see cref="ReviewAt"/> → <see cref="AgentActionReason.HumanApprovalRequired"/> (Review)</item>
/// <item>Input decision Review → <see cref="AgentActionReason.InputHeldForReview"/> (Review)</item>
/// <item>Otherwise → <see cref="AgentActionReason.Permitted"/> (Allow)</item>
/// </list>
/// Every Block rule comes before every Review rule, which come before Allow. So the decision is the strictest that any fact
/// calls for: a higher risk or a stricter input decision never lowers it, and the result is never below the input decision.
/// </remarks>
internal static class AgentActionPolicy
{
    /// <summary>Actions at this risk or above need a person's approval (Review).</summary>
    public const RiskLevel ReviewAt = RiskLevel.High;

    /// <summary>Actions at this risk or above are denied to every agent (Block), whatever it holds.</summary>
    public const RiskLevel DenyAt = RiskLevel.Critical;

    public static AgentActionReason Decide(AgentActionFacts facts)
    {
        // An undefined value is a bug upstream; deciding on it could read it as "low" or "no input decision".
        if (!Enum.IsDefined(facts.Risk))
        {
            throw new ArgumentOutOfRangeException(nameof(facts), facts.Risk, "Unknown risk level.");
        }

        if (facts.InputDecision is { } reported && !Enum.IsDefined(reported))
        {
            throw new ArgumentOutOfRangeException(nameof(facts), reported, "Unknown input decision.");
        }

        if (!facts.AgentKnown)
        {
            return AgentActionReason.UnknownAgent;
        }

        if (!facts.CallerBound)
        {
            return AgentActionReason.CallerNotBoundToAgent;
        }

        if (!facts.ToolKnown)
        {
            return AgentActionReason.UnknownTool;
        }

        if (!facts.ActionKnown)
        {
            return AgentActionReason.UnknownAction;
        }

        if (!facts.CapabilityMatches)
        {
            return AgentActionReason.CapabilityMismatch;
        }

        if (!facts.CapabilityGranted)
        {
            return AgentActionReason.CapabilityNotGranted;
        }

        if (facts.Risk >= DenyAt)
        {
            return AgentActionReason.CriticalActionDenied;
        }

        if (facts.InputDecision == SecurityDecision.Block)
        {
            return AgentActionReason.InputBlocked;
        }

        if (facts.Risk >= ReviewAt)
        {
            return AgentActionReason.HumanApprovalRequired;
        }

        return facts.InputDecision == SecurityDecision.Review
            ? AgentActionReason.InputHeldForReview
            : AgentActionReason.Permitted;
    }
}

/// <summary>What the policy needs to know about one request, established by the authorizer from trusted data.</summary>
/// <param name="AgentKnown">The agent is configured.</param>
/// <param name="CallerBound">The caller that asked is bound to the agent (may act for it).</param>
/// <param name="ToolKnown">The tool is catalogued.</param>
/// <param name="ActionKnown">The action of that tool is catalogued.</param>
/// <param name="CapabilityMatches">The claimed capability is exactly the one the action requires.</param>
/// <param name="CapabilityGranted">The agent holds the capability the action requires.</param>
/// <param name="Risk">The action's risk (<see cref="ActionRiskClassifier"/>).</param>
/// <param name="InputDecision">The input decision the caller reported, if any.</param>
internal readonly record struct AgentActionFacts(
    bool AgentKnown,
    bool CallerBound,
    bool ToolKnown,
    bool ActionKnown,
    bool CapabilityMatches,
    bool CapabilityGranted,
    RiskLevel Risk,
    SecurityDecision? InputDecision);
