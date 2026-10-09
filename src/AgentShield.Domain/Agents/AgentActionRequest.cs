using AgentShield.Domain.Policy;

namespace AgentShield.Domain.Agents;

/// <summary>
/// What an agent proposes to do: call <see cref="Action"/> of <see cref="Tool"/>, claiming <see cref="Capability"/>,
/// submitted by <see cref="Caller"/>. A proposal for the authorization boundary to decide, never an instruction to execute.
/// </summary>
/// <remarks>
/// <para><see cref="Caller"/> is established by authentication (the API client), never by the request body. Everything else
/// is untrusted, and each field is either checked against AgentShield's own data or can only make the decision stricter:
/// the agent ID must name a configured agent bound to the caller, the tool and action a catalogued action, the capability
/// must be exactly the one that action requires, and the agent must hold it. <see cref="InputDecision"/> can raise the
/// decision, never lower it.</para>
/// <para>The request carries no tool arguments. A policy that does not read arguments cannot vouch for them, so accepting
/// them would only suggest a check that does not exist (argument-level policy is future work).</para>
/// </remarks>
/// <param name="Caller">ID of the authenticated caller that submitted the proposal (for HTTP, the API client).</param>
/// <param name="Agent">The agent that proposes the action.</param>
/// <param name="Tool">The tool it wants to call.</param>
/// <param name="Action">The operation of that tool.</param>
/// <param name="Capability">The capability the agent claims authorises the action.</param>
/// <param name="InputDecision">The firewall's decision about the untrusted input behind this action, as reported by the
/// caller (<see langword="null"/> when it reports none). Evidence that can only make the decision stricter.</param>
public sealed record AgentActionRequest(
    string Caller,
    AgentId Agent,
    ToolId Tool,
    ActionName Action,
    Capability Capability,
    SecurityDecision? InputDecision)
{
    public string Caller { get; } = string.IsNullOrWhiteSpace(Caller)
        ? throw new ArgumentException("An authenticated caller is required.", nameof(Caller))
        : Caller;

    public AgentId Agent { get; } = Agent ?? throw new ArgumentNullException(nameof(Agent));

    public ToolId Tool { get; } = Tool ?? throw new ArgumentNullException(nameof(Tool));

    public ActionName Action { get; } = Action ?? throw new ArgumentNullException(nameof(Action));

    public Capability Capability { get; } = Capability ?? throw new ArgumentNullException(nameof(Capability));

    public SecurityDecision? InputDecision { get; } = InputDecision is not { } decision || Enum.IsDefined(decision)
        ? InputDecision
        : throw new ArgumentOutOfRangeException(nameof(InputDecision), InputDecision, "Unknown security decision.");
}
