using AgentShield.Domain.Agents;

namespace AgentShield.Application.Abstractions.Agents;

/// <summary>
/// The agents this deployment knows and the capabilities each was granted. Trusted, read-only configuration; an agent
/// that is not here is unknown and blocked.
/// </summary>
/// <remarks>
/// Today configuration (section <c>AgentAuthorization:Agents</c>, Infrastructure), read once at startup. There is no
/// operation that adds an agent or a capability at runtime, so no request can change what an agent holds.
/// </remarks>
public interface IAgentDirectory
{
    /// <summary>The profile of <paramref name="agent"/>, or <see langword="null"/> when it is not configured.</summary>
    AgentProfile? Find(AgentId agent);

    /// <summary>
    /// The agent whose identity at the tool gateway is the caller <paramref name="clientId"/> (compared exactly; see
    /// <see cref="AgentProfile.GatewayClient"/>), or <see langword="null"/> when that caller is no agent's identity.
    /// </summary>
    AgentProfile? FindByGatewayClient(string clientId);
}
