using System.Collections.Frozen;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Domain.Agents;
using Microsoft.Extensions.Options;

namespace AgentShield.Infrastructure.Agents;

/// <summary>
/// The agent directory built once from validated configuration (<see cref="AgentDirectoryOptions"/>). Immutable: there is
/// no way to add an agent, a capability, a bound client or a gateway identity after startup.
/// </summary>
internal sealed class ConfiguredAgentDirectory : IAgentDirectory
{
    private readonly FrozenDictionary<AgentId, AgentProfile> _profiles;
    private readonly FrozenDictionary<string, AgentProfile> _byGatewayClient;

    public ConfiguredAgentDirectory(IOptions<AgentDirectoryOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // The value objects re-check every name, so options that skipped validation fail here rather than half-load.
        _profiles = options.Value.Agents
            .Select(agent => new AgentProfile(
                new AgentId(agent.Key),
                agent.Value.Capabilities.Select(capability => new Capability(capability)),
                agent.Value.Clients,
                agent.Value.GatewayClient))
            .ToFrozenDictionary(profile => profile.Id);

        // One agent per gateway client: a client that identified two agents would throw here (validation rejects it first).
        _byGatewayClient = _profiles.Values
            .Where(profile => profile.GatewayClient is not null)
            .ToFrozenDictionary(profile => profile.GatewayClient!, StringComparer.Ordinal);
    }

    /// <summary>How many agents are configured.</summary>
    public int Count => _profiles.Count;

    public AgentProfile? Find(AgentId agent)
    {
        ArgumentNullException.ThrowIfNull(agent);
        return _profiles.GetValueOrDefault(agent);
    }

    public AgentProfile? FindByGatewayClient(string clientId)
    {
        ArgumentNullException.ThrowIfNull(clientId);
        return _byGatewayClient.GetValueOrDefault(clientId);
    }
}
