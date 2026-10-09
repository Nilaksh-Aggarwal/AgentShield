using System.Collections.Frozen;

namespace AgentShield.Domain.Agents;

/// <summary>
/// An agent AgentShield knows, the capabilities it was granted, and the callers (authenticated API clients, typically the
/// runtime that executes the agent's tool calls) allowed to request decisions on its behalf. Trusted data from
/// AgentShield's configuration; nothing an agent sends can add to it.
/// </summary>
/// <remarks>
/// <para>Both sets are copied when the profile is built and cannot change afterwards, so no later code path (and no request)
/// can grant a capability to an existing profile or let another caller act for the agent.</para>
/// <para>The caller binding means that holding the permission to ask for decisions does not let a client speak for every
/// agent: a runtime that names an agent it is not bound to is blocked, so one compromised runtime cannot borrow another
/// agent's grants.</para>
/// <para><see cref="GatewayClient"/> goes one step further for the tool gateway: that caller's credential <em>is</em> this
/// agent. A request through the gateway names no agent; the gateway takes the agent from the authenticated caller, so a
/// runtime holding one agent's credential cannot act as another (docs/security/tool-gateway.md).</para>
/// </remarks>
public sealed record AgentProfile
{
    public AgentProfile(AgentId id, IEnumerable<Capability> capabilities, IEnumerable<string> callers, string? gatewayClient = null)
    {
        ArgumentNullException.ThrowIfNull(id);
        ArgumentNullException.ThrowIfNull(capabilities);
        ArgumentNullException.ThrowIfNull(callers);

        var grants = capabilities.ToFrozenSet();
        if (grants.Contains(null!))
        {
            throw new ArgumentException("Capabilities cannot contain null entries.", nameof(capabilities));
        }

        var bound = callers.ToFrozenSet(StringComparer.Ordinal);
        if (bound.Any(string.IsNullOrWhiteSpace))
        {
            throw new ArgumentException("Callers cannot contain blank entries.", nameof(callers));
        }

        // The gateway identity is one of the callers bound to the agent, so the authorization boundary's caller binding
        // holds for every request the gateway makes as this agent.
        if (gatewayClient is not null && !bound.Contains(gatewayClient))
        {
            throw new ArgumentException("The gateway client must be one of the callers bound to the agent.", nameof(gatewayClient));
        }

        Id = id;
        Capabilities = grants;
        Callers = bound;
        GatewayClient = gatewayClient;
    }

    public AgentId Id { get; }

    /// <summary>The granted capabilities, exactly as configured.</summary>
    public IReadOnlySet<Capability> Capabilities { get; }

    /// <summary>IDs of the callers allowed to request decisions for this agent, exactly as configured.</summary>
    public IReadOnlySet<string> Callers { get; }

    /// <summary>
    /// ID of the caller whose credential identifies this agent at the tool gateway, or <see langword="null"/> when the agent
    /// cannot execute tools through it. Always one of <see cref="Callers"/>.
    /// </summary>
    public string? GatewayClient { get; }

    /// <summary>Whether the agent was granted exactly <paramref name="capability"/>.</summary>
    public bool Holds(Capability capability)
    {
        ArgumentNullException.ThrowIfNull(capability);
        return Capabilities.Contains(capability);
    }

    /// <summary>Whether <paramref name="caller"/> (compared exactly) may request decisions for this agent.</summary>
    public bool AcceptsCaller(string caller)
    {
        ArgumentNullException.ThrowIfNull(caller);
        return Callers.Contains(caller);
    }
}
