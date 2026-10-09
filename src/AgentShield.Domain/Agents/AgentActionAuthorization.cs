using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;

namespace AgentShield.Domain.Agents;

/// <summary>
/// The authorization boundary's verdict on one <see cref="AgentActionRequest"/>: the decision, the reason for it and the
/// risk of the action. It authorises nothing by itself and executes nothing; only <see cref="SecurityDecision.Allow"/> means
/// the caller may go on to execute the action.
/// </summary>
/// <remarks>
/// <para>The decision is derived from the reason (<see cref="AgentActionReasons.DecisionFor"/>), never set independently,
/// so the two cannot disagree. Allow and Review are possible only for a request whose agent, tool, action and capability
/// were all recognised; a reason that says something was unknown must not carry it as recognised.</para>
/// <para><see cref="Risk"/> is the risk of the action, not of the request: a Low-risk read that the agent may not perform
/// is Low risk and blocked.</para>
/// </remarks>
public sealed record AgentActionAuthorization
{
    public AgentActionAuthorization(AgentActionReason reason, RiskLevel risk, RecognisedAgentAction recognised)
    {
        ArgumentNullException.ThrowIfNull(recognised);

        var decision = AgentActionReasons.DecisionFor(reason);
        if (!Enum.IsDefined(risk))
        {
            throw new ArgumentOutOfRangeException(nameof(risk), risk, "Unknown risk level.");
        }

        if (decision != SecurityDecision.Block && !recognised.IsComplete)
        {
            throw new ArgumentException("Only a request whose agent, tool, action and capability were all recognised can be allowed or reviewed.", nameof(recognised));
        }

        var contradicted = reason switch
        {
            AgentActionReason.UnknownAgent => recognised.Agent is not null,
            AgentActionReason.UnknownTool => recognised.Tool is not null,
            AgentActionReason.UnknownAction => recognised.Action is not null,
            _ => false,
        };
        if (contradicted)
        {
            throw new ArgumentException("A reason that names something unknown cannot carry it as recognised.", nameof(recognised));
        }

        Reason = reason;
        Decision = decision;
        Risk = risk;
        Recognised = recognised;
    }

    public SecurityDecision Decision { get; }

    public AgentActionReason Reason { get; }

    public RiskLevel Risk { get; }

    /// <summary>The request's identifiers that AgentShield's own configuration recognises (audit data).</summary>
    public RecognisedAgentAction Recognised { get; }
}

/// <summary>
/// The identifiers of an action request that AgentShield's own configuration recognises: the agent from the agent directory,
/// the tool, action and capability from the tool catalogue. <see langword="null"/> where the request named something
/// AgentShield does not know.
/// </summary>
/// <remarks>
/// What gets recorded about a request (audit log, activity history) is taken from here, so a record only ever holds names
/// from AgentShield's own vocabulary. A name the caller made up is recorded as unknown, never verbatim: an agent cannot use
/// the tool or agent field to write arbitrary text into the history.
/// </remarks>
public sealed record RecognisedAgentAction
{
    public RecognisedAgentAction(AgentId? agent, ToolId? tool, ActionName? action, Capability? capability)
    {
        if (tool is null && action is not null)
        {
            throw new ArgumentException("An action cannot be recognised for an unrecognised tool.", nameof(action));
        }

        Agent = agent;
        Tool = tool;
        Action = action;
        Capability = capability;
    }

    public AgentId? Agent { get; }

    public ToolId? Tool { get; }

    public ActionName? Action { get; }

    public Capability? Capability { get; }

    /// <summary>Whether every identifier was recognised.</summary>
    public bool IsComplete => Agent is not null && Tool is not null && Action is not null && Capability is not null;
}
