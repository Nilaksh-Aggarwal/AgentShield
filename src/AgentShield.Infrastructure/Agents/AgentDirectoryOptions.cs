using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.Context;
using AgentShield.Domain.Agents;
using Microsoft.Extensions.Options;

namespace AgentShield.Infrastructure.Agents;

/// <summary>
/// The agents this deployment knows (section <c>AgentAuthorization</c>), keyed by agent ID:
/// <c>AgentAuthorization:Agents:{agentId}:Capabilities</c> and <c>...:Clients</c>. Validated at startup.
/// </summary>
/// <remarks>
/// Operator configuration, like the API clients. The committed appsettings.json configures no agent, so a deployment that
/// does not configure any blocks every agent action (<c>UnknownAgent</c>). The demo agents live in
/// appsettings.Development.json only.
/// </remarks>
public sealed class AgentDirectoryOptions
{
    public const string SectionName = "AgentAuthorization";

    public IDictionary<string, AgentOptions> Agents { get; } = new Dictionary<string, AgentOptions>(StringComparer.Ordinal);
}

/// <summary>One agent (section <c>AgentAuthorization:Agents:{agentId}</c>).</summary>
public sealed class AgentOptions
{
    /// <summary>Capabilities granted to the agent, each one the tool catalogue requires. Empty: known, allowed nothing.</summary>
    public IList<string> Capabilities { get; } = [];

    /// <summary>
    /// IDs of the API clients (<c>Authentication:Clients</c>, holding <c>agent:authorize</c> or <c>tool:execute</c>) allowed to
    /// act for this agent: typically the one runtime that executes its tool calls. At least one.
    /// </summary>
    public IList<string> Clients { get; } = [];

    /// <summary>
    /// Optional: the ID of the API client whose credential identifies this agent at the tool gateway. Requests that client
    /// sends to <c>POST /api/v1/agent/tools/execute</c> act as this agent and no other. It must be one of
    /// <see cref="Clients"/>, hold <c>tool:execute</c>, and be the gateway client of no other agent. Without it, the agent
    /// cannot execute tools through the gateway.
    /// </summary>
    public string? GatewayClient { get; set; }
}

/// <summary>
/// Startup validation of <see cref="AgentDirectoryOptions"/>: agent IDs and capabilities must be valid names, every capability
/// must be one the tool catalogue requires (a grant nothing requires is a typo or a stale entry), every agent must be bound
/// to at least one configured client that may act for it, and the tool gateway's identities must be unambiguous (each
/// client holding <c>tool:execute</c> is the gateway client of exactly one agent). Messages name agents and configured
/// clients, never a rejected value.
/// </summary>
internal sealed class AgentDirectoryOptionsValidator(IToolCatalog catalog, IApiClientDirectory clients) : IValidateOptions<AgentDirectoryOptions>
{
    public ValidateOptionsResult Validate(string? name, AgentDirectoryOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var failures = new List<string>();
        var gatewayIdentities = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var (agentId, agent) in options.Agents)
        {
            if (!AgentIdentifiers.IsValidName(agentId))
            {
                failures.Add($"{AgentDirectoryOptions.SectionName}:Agents: an agent ID must be 1-{AgentIdentifiers.MaxLength} characters of lower-case letters, digits, '.', '_' and '-', starting with a letter or digit.");
                continue;
            }

            var prefix = $"{AgentDirectoryOptions.SectionName}:Agents:{agentId}";
            foreach (var capability in agent.Capabilities)
            {
                if (!AgentIdentifiers.IsValidCapability(capability))
                {
                    failures.Add($"{prefix}:Capabilities contains a value that is not a capability ('resource:operation').");
                }
                else if (!catalog.Capabilities.Contains(new Capability(capability)))
                {
                    failures.Add($"{prefix}:Capabilities contains a capability no catalogued tool action requires.");
                }
            }

            if (agent.Clients.Count == 0)
            {
                failures.Add($"{prefix}:Clients is empty: an agent must be bound to at least one API client that may act for it.");
            }

            if (agent.Clients.Any(client => !clients.AgentAuthorizationClientIds.Contains(client) && !clients.ToolExecutionClientIds.Contains(client)))
            {
                failures.Add($"{prefix}:Clients names a client that is configured with neither the agent:authorize nor the tool:execute permission.");
            }

            if (agent.GatewayClient is not { } gatewayClient)
            {
                continue;
            }

            // The rejected value is not quoted: it is checked against the configured clients first.
            if (!clients.ToolExecutionClientIds.Contains(gatewayClient))
            {
                failures.Add($"{prefix}:GatewayClient names a client that is not configured with the tool:execute permission.");
                continue;
            }

            if (!agent.Clients.Contains(gatewayClient, StringComparer.Ordinal))
            {
                failures.Add($"{prefix}:GatewayClient must also be listed in {prefix}:Clients.");
            }

            gatewayIdentities[gatewayClient] = gatewayIdentities.GetValueOrDefault(gatewayClient) + 1;
        }

        // Every client that may call the tool gateway is exactly one agent: no client without an identity, none with two.
        foreach (var client in clients.ToolExecutionClientIds.Order(StringComparer.Ordinal))
        {
            var identities = gatewayIdentities.GetValueOrDefault(client);
            if (identities == 0)
            {
                failures.Add($"Authentication:Clients:{client} holds tool:execute but is no agent's {AgentDirectoryOptions.SectionName}:Agents:{{agentId}}:GatewayClient.");
            }
            else if (identities > 1)
            {
                failures.Add($"Authentication:Clients:{client} is the GatewayClient of {identities} agents: a gateway client must identify exactly one agent.");
            }
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
