using AgentShield.Application.Abstractions.Agents;
using AgentShield.Domain.Agents;
using AgentShield.Infrastructure.Agents;
using AgentShield.UnitTests.Infrastructure.AiCapacity;
using Microsoft.Extensions.Options;

namespace AgentShield.UnitTests.Infrastructure.Agents;

/// <summary>
/// The tool gateway's agent identities (<c>AgentAuthorization:Agents:{id}:GatewayClient</c>): validated at startup so that
/// every client that may call the gateway is exactly one agent, then looked up exactly.
/// </summary>
public sealed class AgentGatewayIdentityTests
{
    private readonly AgentDirectoryOptionsValidator _validator = new(
        new KnowledgeCatalog(),
        new StaticClientDirectory
        {
            AgentAuthorizationClientIds = new HashSet<string> { "support-runtime" },
            ToolExecutionClientIds = new HashSet<string> { "support-gateway", "research-gateway" },
        });

    [Fact]
    public void Validate_EachToolExecutionClient_TheGatewayClientOfExactlyOneAgent_Passes()
    {
        var options = Options(
            ("support-agent", ["support-runtime", "support-gateway"], "support-gateway"),
            ("research-agent", ["research-gateway"], "research-gateway"),
            ("idle-agent", ["support-runtime"], null));

        Assert.True(_validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void Validate_AToolExecutionClientThatIsNoAgentsIdentity_Fails_NamingTheClient()
    {
        var result = _validator.Validate(null, Options(("support-agent", ["support-gateway"], "support-gateway")));

        Assert.True(result.Failed);
        Assert.Contains("Authentication:Clients:research-gateway holds tool:execute but is no agent's", result.FailureMessage, StringComparison.Ordinal);
        Assert.DoesNotContain("support-gateway", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_OneClientAsTheIdentityOfTwoAgents_Fails()
    {
        var options = Options(
            ("support-agent", ["support-gateway"], "support-gateway"),
            ("finance-agent", ["support-gateway"], "support-gateway"),
            ("research-agent", ["research-gateway"], "research-gateway"));

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("Authentication:Clients:support-gateway is the GatewayClient of 2 agents", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("support-runtime")]
    [InlineData("not-a-client-zq7")]
    [InlineData("SUPPORT-GATEWAY")]
    public void Validate_AGatewayClientWithoutToolExecute_Fails_WithoutQuotingIt(string gatewayClient)
    {
        var options = Options(("support-agent", ["support-runtime", gatewayClient], gatewayClient), ("research-agent", ["research-gateway"], "research-gateway"));

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("support-agent:GatewayClient names a client that is not configured with the tool:execute permission.", result.FailureMessage, StringComparison.Ordinal);
        Assert.DoesNotContain("zq7", result.FailureMessage, StringComparison.Ordinal);
        Assert.DoesNotContain("SUPPORT-GATEWAY", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_AGatewayClientNotAmongTheAgentsClients_Fails()
    {
        var options = Options(("support-agent", ["support-runtime"], "support-gateway"), ("research-agent", ["research-gateway"], "research-gateway"));

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("AgentAuthorization:Agents:support-agent:GatewayClient must also be listed in AgentAuthorization:Agents:support-agent:Clients.", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_AToolExecutionClient_MayBeBoundToAnAgent_WithoutAgentAuthorize()
    {
        // A gateway-only credential (tool:execute, no agent:authorize) is a client that may act for its agent.
        var options = Options(("support-agent", ["support-gateway"], "support-gateway"), ("research-agent", ["research-gateway"], "research-gateway"));

        Assert.True(_validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void FindByGatewayClient_IsExact_AndAnswersOnlyForTheConfiguredIdentity()
    {
        var directory = Directory(Options(
            ("support-agent", ["support-runtime", "support-gateway"], "support-gateway"),
            ("research-agent", ["research-gateway"], "research-gateway")));

        Assert.Equal(new AgentId("support-agent"), directory.FindByGatewayClient("support-gateway")!.Id);
        Assert.Equal("support-gateway", directory.FindByGatewayClient("support-gateway")!.GatewayClient);
        Assert.Equal(new AgentId("research-agent"), directory.FindByGatewayClient("research-gateway")!.Id);
        Assert.Null(directory.FindByGatewayClient("support-runtime"));
        Assert.Null(directory.FindByGatewayClient("Support-Gateway"));
        Assert.Null(directory.FindByGatewayClient("support-gateway "));
        Assert.Null(directory.FindByGatewayClient(string.Empty));
        Assert.Throws<ArgumentNullException>(() => directory.FindByGatewayClient(null!));
    }

    [Fact]
    public void FindByGatewayClient_IsBuiltOnce_SoChangingTheOptionsAfterwardsChangesNoIdentity()
    {
        var options = Options(("support-agent", ["support-gateway", "research-gateway"], "support-gateway"));
        var directory = Directory(options);

        options.Agents["support-agent"].GatewayClient = "research-gateway";
        options.Agents["rogue-agent"] = new AgentOptions { GatewayClient = "rogue-gateway" };

        Assert.Equal(new AgentId("support-agent"), directory.FindByGatewayClient("support-gateway")!.Id);
        Assert.Null(directory.FindByGatewayClient("research-gateway"));
        Assert.Null(directory.FindByGatewayClient("rogue-gateway"));
    }

    [Fact]
    public void Directory_UnvalidatedIdentities_FailToLoad()
    {
        // A gateway client outside the agent's clients, or one client for two agents, never half-loads.
        Assert.ThrowsAny<ArgumentException>(() => Directory(Options(("support-agent", ["support-runtime"], "support-gateway"))));
        Assert.ThrowsAny<ArgumentException>(() => Directory(Options(
            ("support-agent", ["support-gateway"], "support-gateway"),
            ("finance-agent", ["support-gateway"], "support-gateway"))));
    }

    private static ConfiguredAgentDirectory Directory(AgentDirectoryOptions options) => new(Microsoft.Extensions.Options.Options.Create(options));

    private static AgentDirectoryOptions Options(params (string Id, string[] Clients, string? GatewayClient)[] agents)
    {
        var options = new AgentDirectoryOptions();
        foreach (var (id, clients, gatewayClient) in agents)
        {
            var agent = new AgentOptions { GatewayClient = gatewayClient };
            agent.Capabilities.Add("knowledge:read");
            foreach (var client in clients)
            {
                agent.Clients.Add(client);
            }

            options.Agents[id] = agent;
        }

        return options;
    }

    private sealed class KnowledgeCatalog : IToolCatalog
    {
        public IReadOnlyCollection<ToolActionDefinition> Actions { get; } = [];

        public IReadOnlySet<Capability> Capabilities { get; } = new HashSet<Capability> { new("knowledge:read") };

        public bool HasTool(ToolId tool) => false;

        public ToolActionDefinition? Find(ToolId tool, ActionName action) => null;
    }
}
