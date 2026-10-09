using AgentShield.Application.Abstractions.Agents;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Security.Agents;

namespace AgentShield.SecurityTests.Agents;

/// <summary>Agents, callers and requests for the authorization boundary tests, against the production reference catalogue.</summary>
internal static class AgentTestData
{
    /// <summary>The runtime bound to the support, research and operations agents.</summary>
    public const string RuntimeA = "runtime-a";

    /// <summary>The runtime bound to the finance agent only.</summary>
    public const string RuntimeB = "runtime-b";

    public static readonly ReferenceToolCatalog Catalog = new();

    public static readonly InMemoryAgentDirectory TestAgents = new(
        new AgentProfile(new AgentId("support-agent"), Capabilities("data:read", "email:read", "email:draft", "email:send"), [RuntimeA]),
        new AgentProfile(new AgentId("research-agent"), Capabilities("data:read", "file:read", "browser:navigate"), [RuntimeA]),
        new AgentProfile(new AgentId("operations-agent"), Capabilities("data:read", "data:write", "file:read", "file:write", "customer:write"), [RuntimeA]),
        new AgentProfile(new AgentId("finance-agent"), Capabilities("data:read", "payment:execute"), [RuntimeB]),
        new AgentProfile(new AgentId("idle-agent"), [], [RuntimeA]));

    public static AgentActionAuthorizer Authorizer { get; } = new(Catalog, TestAgents);

    public static AgentActionRequest Request(
        string agent,
        string tool,
        string action,
        string capability,
        SecurityDecision? inputDecision = null,
        string caller = RuntimeA) =>
        new(caller, new AgentId(agent), new ToolId(tool), new ActionName(action), new Capability(capability), inputDecision);

    public static AgentActionAuthorization Authorize(string agent, string tool, string action, string capability, SecurityDecision? inputDecision = null, string caller = RuntimeA) =>
        Authorizer.Authorize(Request(agent, tool, action, capability, inputDecision, caller));

    /// <summary>Allow &lt; Review &lt; Block, for "never lower than" assertions.</summary>
    public static int Rank(SecurityDecision decision) => decision switch
    {
        SecurityDecision.Allow => 0,
        SecurityDecision.Review => 1,
        SecurityDecision.Block => 2,
        _ => throw new ArgumentOutOfRangeException(nameof(decision), decision, null),
    };

    /// <summary>An absent input decision counts as Allow: it adds nothing.</summary>
    public static int Rank(SecurityDecision? decision) => decision is { } value ? Rank(value) : 0;

    private static Capability[] Capabilities(params string[] values) => [.. values.Select(value => new Capability(value))];
}

/// <summary>A fixed set of agent profiles.</summary>
internal sealed class InMemoryAgentDirectory(params AgentProfile[] profiles) : IAgentDirectory
{
    public IReadOnlyList<AgentProfile> Profiles { get; } = profiles;

    public AgentProfile? Find(AgentId agent) => Profiles.SingleOrDefault(profile => profile.Id == agent);

    public AgentProfile? FindByGatewayClient(string clientId) => Profiles.SingleOrDefault(profile => profile.GatewayClient == clientId);
}
