using AgentShield.Domain.Policy;

namespace AgentShield.Domain.Agents;

/// <summary>
/// Why the authorization boundary decided as it did: a coarse, stable reason code, safe to return to the caller and to
/// record. Each reason has exactly one decision (<see cref="AgentActionReasons.DecisionFor"/>), so a reason and a decision
/// can never disagree.
/// </summary>
/// <remarks>The order of the policy rules that produce these reasons: docs/security/agent-action-authorization.md.</remarks>
public enum AgentActionReason
{
    /// <summary>Allow: the agent holds the capability the action requires, and the action is Low or Medium risk.</summary>
    Permitted = 1,

    /// <summary>Review: the agent holds the capability, but the action is High risk and needs a person's approval.</summary>
    HumanApprovalRequired = 2,

    /// <summary>Review: the action would be permitted, but the input behind it was held for review.</summary>
    InputHeldForReview = 3,

    /// <summary>Block: the agent is not configured in AgentShield.</summary>
    UnknownAgent = 4,

    /// <summary>Block: the tool is not in AgentShield's tool catalogue.</summary>
    UnknownTool = 5,

    /// <summary>Block: the tool is catalogued, but this action of it is not.</summary>
    UnknownAction = 6,

    /// <summary>Block: the capability the agent claimed is not the one the action requires.</summary>
    CapabilityMismatch = 7,

    /// <summary>Block: the agent was not granted the capability the action requires.</summary>
    CapabilityNotGranted = 8,

    /// <summary>Block: the action is Critical risk (financial, credentials, destructive, privilege change), which no agent
    /// may perform on its own authority, whatever it holds.</summary>
    CriticalActionDenied = 9,

    /// <summary>Block: the input behind the action was blocked by the firewall.</summary>
    InputBlocked = 10,

    /// <summary>Block: the agent is configured, but the caller that asked is not bound to it, so it may not act for it.</summary>
    CallerNotBoundToAgent = 11,
}

/// <summary>The decision each <see cref="AgentActionReason"/> stands for.</summary>
public static class AgentActionReasons
{
    /// <summary>The decision of <paramref name="reason"/>. Only <see cref="AgentActionReason.Permitted"/> allows.</summary>
    public static SecurityDecision DecisionFor(AgentActionReason reason) => reason switch
    {
        AgentActionReason.Permitted => SecurityDecision.Allow,
        AgentActionReason.HumanApprovalRequired or AgentActionReason.InputHeldForReview => SecurityDecision.Review,
        AgentActionReason.UnknownAgent
            or AgentActionReason.UnknownTool
            or AgentActionReason.UnknownAction
            or AgentActionReason.CapabilityMismatch
            or AgentActionReason.CapabilityNotGranted
            or AgentActionReason.CriticalActionDenied
            or AgentActionReason.InputBlocked
            or AgentActionReason.CallerNotBoundToAgent => SecurityDecision.Block,
        _ => throw new ArgumentOutOfRangeException(nameof(reason), reason, "Unknown agent action reason."),
    };
}
