using AgentShield.Application.Abstractions.Agents;
using AgentShield.Domain.Agents;
using AgentShield.Infrastructure.Agents;
using AgentShield.UnitTests.Infrastructure.AiCapacity;
using Microsoft.Extensions.Options;

namespace AgentShield.UnitTests.Infrastructure.Agents;

/// <summary>
/// The configured agent directory: validated against the tool catalogue at startup, then an immutable lookup by exact ID.
/// </summary>
public sealed class AgentDirectoryTests
{
    private readonly AgentDirectoryOptionsValidator _validator = new(
        new FixedCatalog("data:read", "email:send", "payment:execute"),
        new StaticClientDirectory { AgentAuthorizationClientIds = new HashSet<string> { "support-runtime", "finance-runtime" } });

    [Fact]
    public void Validate_KnownAgentsWithCatalogueCapabilities_Pass()
    {
        var options = Options(("support-agent", ["data:read", "email:send"]), ("idle-agent", []));

        Assert.True(_validator.Validate(null, options).Succeeded);
    }

    [Fact]
    public void Validate_NoAgents_Passes_SoAnUnconfiguredDeploymentBlocksEveryAgent()
    {
        Assert.True(_validator.Validate(null, new AgentDirectoryOptions()).Succeeded);
        Assert.Null(Directory(new AgentDirectoryOptions()).Find(new AgentId("support-agent")));
    }

    [Theory]
    [InlineData("Support-Agent")]
    [InlineData("support agent")]
    [InlineData("-agent")]
    [InlineData("")]
    public void Validate_InvalidAgentId_Fails_WithoutQuotingIt(string agentId)
    {
        var result = _validator.Validate(null, Options((agentId, ["data:read"])));

        Assert.True(result.Failed);
        if (agentId.Length > 0)
        {
            Assert.DoesNotContain(agentId, result.FailureMessage, StringComparison.Ordinal);
        }
    }

    [Theory]
    [InlineData("data")]
    [InlineData("data:*")]
    [InlineData("*")]
    [InlineData("Data:Read")]
    [InlineData("data:read ")]
    public void Validate_MalformedCapability_Fails_WithoutQuotingIt(string capability)
    {
        var result = _validator.Validate(null, Options(("support-agent", [capability])));

        Assert.True(result.Failed);
        Assert.Contains("support-agent", result.FailureMessage, StringComparison.Ordinal);
        Assert.DoesNotContain(capability, result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_CapabilityNoCatalogueActionRequires_Fails()
    {
        // A grant nothing requires is a typo or stale entry, never a wildcard.
        var result = _validator.Validate(null, Options(("support-agent", ["data:read", "admin:all"])));

        Assert.True(result.Failed);
        Assert.Contains("no catalogued tool action requires", result.FailureMessage, StringComparison.Ordinal);
        Assert.DoesNotContain("admin:all", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_InvalidAgentId_SaysWhatAnAgentIdMustBe()
    {
        var result = _validator.Validate(null, Options(("Support-Agent", ["data:read"])));

        Assert.Equal(
            "AgentAuthorization:Agents: an agent ID must be 1-64 characters of lower-case letters, digits, '.', '_' and '-', starting with a letter or digit.",
            Assert.Single(result.Failures!));
    }

    [Fact]
    public void Validate_InvalidAgentIdWithFurtherErrors_ReportsOnlyTheId_SoItIsNeverQuoted()
    {
        // Mutation testing (M10): without stopping at the invalid ID, the capability and client messages, which start with
        // the agent ID, would repeat the rejected value.
        var options = Bound("rogue-runtime", ("Bad Agent Zq7", ["admin:all", "data:*"]));

        var result = _validator.Validate(null, options);

        var failure = Assert.Single(result.Failures!);
        Assert.DoesNotContain("Zq7", failure, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_OneBoundClientWithoutAgentAuthorize_AmongValidOnes_Fails()
    {
        // Mutation testing (M10): "any" bound client lacking the permission fails, not only "all" of them.
        var options = Bound("support-runtime", ("support-agent", ["data:read"]));
        options.Agents["support-agent"].Clients.Add("analysis-only-client");

        var result = _validator.Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("support-agent:Clients names a client that is configured with neither the agent:authorize nor the tool:execute permission.", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_AgentBoundToNoClient_Fails()
    {
        var result = _validator.Validate(null, Bound(string.Empty, ("support-agent", ["data:read"])));

        Assert.True(result.Failed);
        Assert.Contains("support-agent:Clients is empty", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("analysis-only-client")]
    [InlineData("Support-Runtime")]
    [InlineData("support-runtime ")]
    public void Validate_AgentBoundToAClientWithoutAgentAuthorize_Fails_WithoutQuotingIt(string client)
    {
        // Only clients that can call the boundary can be bound; a typo would otherwise silently disable the agent.
        var result = _validator.Validate(null, Bound(client, ("support-agent", ["data:read"])));

        Assert.True(result.Failed);
        Assert.Contains("agent:authorize", result.FailureMessage, StringComparison.Ordinal);
        Assert.DoesNotContain(client.Trim(), result.FailureMessage.Replace("support-agent", string.Empty, StringComparison.Ordinal), StringComparison.Ordinal);
    }

    [Fact]
    public void Directory_KeepsExactlyTheBoundClients()
    {
        var directory = Directory(Bound("finance-runtime", ("finance-agent", ["payment:execute"])));

        var finance = directory.Find(new AgentId("finance-agent"))!;

        Assert.True(finance.AcceptsCaller("finance-runtime"));
        Assert.False(finance.AcceptsCaller("support-runtime"));
    }

    [Fact]
    public void Directory_FindsConfiguredAgentsByExactId_WithExactlyTheirGrants()
    {
        var directory = Directory(Options(("support-agent", ["data:read", "email:send"]), ("finance-agent", ["payment:execute"])));

        var support = directory.Find(new AgentId("support-agent"));

        Assert.NotNull(support);
        Assert.Equal(new AgentId("support-agent"), support.Id);
        Assert.Equal(new HashSet<Capability> { new("data:read"), new("email:send") }, support.Capabilities);
        Assert.False(support.Holds(new Capability("payment:execute")));
        Assert.Null(directory.Find(new AgentId("support-agent-2")));
        Assert.Null(directory.Find(new AgentId("support")));
        Assert.Equal(2, directory.Count);
    }

    [Fact]
    public void Directory_IsBuiltOnce_SoChangingTheOptionsAfterwardsGrantsNothing()
    {
        var options = Options(("support-agent", ["data:read"]));
        var directory = Directory(options);

        options.Agents["support-agent"].Capabilities.Add("payment:execute");
        options.Agents["rogue-agent"] = new AgentOptions();

        Assert.False(directory.Find(new AgentId("support-agent"))!.Holds(new Capability("payment:execute")));
        Assert.Null(directory.Find(new AgentId("rogue-agent")));
    }

    [Fact]
    public void Directory_UnvalidatedOptions_FailToLoad_RatherThanHalfLoad()
    {
        Assert.ThrowsAny<ArgumentException>(() => Directory(Options(("Bad Agent", ["data:read"]))));
        Assert.ThrowsAny<ArgumentException>(() => Directory(Options(("support-agent", ["data:*"]))));
    }

    private static ConfiguredAgentDirectory Directory(AgentDirectoryOptions options) => new(Microsoft.Extensions.Options.Options.Create(options));

    private static AgentDirectoryOptions Options(params (string Id, string[] Capabilities)[] agents) =>
        Bound("support-runtime", agents);

    private static AgentDirectoryOptions Bound(string client, params (string Id, string[] Capabilities)[] agents)
    {
        var options = new AgentDirectoryOptions();
        foreach (var (id, capabilities) in agents)
        {
            var agent = new AgentOptions();
            if (client.Length > 0)
            {
                agent.Clients.Add(client);
            }

            foreach (var capability in capabilities)
            {
                agent.Capabilities.Add(capability);
            }

            options.Agents[id] = agent;
        }

        return options;
    }

    private sealed class FixedCatalog(params string[] capabilities) : IToolCatalog
    {
        public IReadOnlyCollection<ToolActionDefinition> Actions { get; } = [];

        public IReadOnlySet<Capability> Capabilities { get; } = capabilities.Select(capability => new Capability(capability)).ToHashSet();

        public bool HasTool(ToolId tool) => false;

        public ToolActionDefinition? Find(ToolId tool, ActionName action) => null;
    }
}
