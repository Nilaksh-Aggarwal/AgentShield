using AgentShield.Domain.Agents;

namespace AgentShield.Application.Abstractions.Agents;

/// <summary>
/// The agent action authorization boundary: decides whether an agent may perform a proposed tool action (Allow, Review or
/// Block). Deterministic; implemented in the Security layer.
/// </summary>
/// <remarks>
/// <para>It decides; it never executes. The agent proposes, this boundary decides, and a tool executor may act only on an
/// Allow. AgentShield has no tool executor today, so enforcing the decision is the caller's job
/// (docs/decisions/0020-agent-action-authorization-boundary.md).</para>
/// <para>Nothing the agent sends can grant a capability or lower the decision: agent profiles and tool definitions come from
/// AgentShield's own configuration (<see cref="IAgentDirectory"/>, <see cref="IToolCatalog"/>), the claimed capability must
/// match exactly, and the reported input decision can only make the verdict stricter. Anything unknown is blocked.</para>
/// </remarks>
public interface IAgentActionAuthorizer
{
    AgentActionAuthorization Authorize(AgentActionRequest request);
}
