using AgentShield.Domain.Agents;
using AgentShield.Domain.Risk;
using AgentShield.Security.Agents;

namespace AgentShield.SecurityTests.Agents;

/// <summary>
/// The reference tool catalogue is security policy: every action's required capability and risk is pinned here, so a change
/// to it is a deliberate, reviewed decision.
/// </summary>
public sealed class ReferenceToolCatalogTests
{
    private readonly ReferenceToolCatalog _catalog = new();

    [Theory]
    [InlineData("data", "describe", "data:read", RiskLevel.Low)]
    [InlineData("data", "read", "data:read", RiskLevel.Low)]
    [InlineData("data", "write", "data:write", RiskLevel.Medium)]
    [InlineData("data", "delete", "data:delete", RiskLevel.Critical)]
    [InlineData("email", "read", "email:read", RiskLevel.Low)]
    [InlineData("email", "draft", "email:draft", RiskLevel.Medium)]
    [InlineData("email", "send", "email:send", RiskLevel.High)]
    [InlineData("file", "read", "file:read", RiskLevel.Low)]
    [InlineData("file", "write", "file:write", RiskLevel.Medium)]
    [InlineData("browser", "navigate", "browser:navigate", RiskLevel.High)]
    [InlineData("browser", "submit", "browser:submit", RiskLevel.High)]
    [InlineData("customer", "update", "customer:write", RiskLevel.High)]
    [InlineData("payment", "execute", "payment:execute", RiskLevel.Critical)]
    [InlineData("secrets", "read", "secrets:read", RiskLevel.Critical)]
    [InlineData("identity", "grant", "identity:grant", RiskLevel.Critical)]
    [InlineData("knowledge", "lookup", "knowledge:read", RiskLevel.Low)]
    public void Find_EachCataloguedAction_HasItsPinnedCapabilityAndRisk(string tool, string action, string capability, RiskLevel risk)
    {
        var definition = _catalog.Find(new ToolId(tool), new ActionName(action));

        Assert.NotNull(definition);
        Assert.Equal((new ToolId(tool), new ActionName(action)), (definition.Tool, definition.Action));
        Assert.Equal(new Capability(capability), definition.RequiredCapability);
        Assert.Equal(risk, ActionRiskClassifier.Classify(definition.Effects));
    }

    [Fact]
    public void Actions_AreExactlyTheSixteenPinnedOnes_CoveringEveryRiskLevel()
    {
        Assert.Equal(16, _catalog.Actions.Count);
        Assert.Equal(16, _catalog.Actions.Select(definition => (definition.Tool, definition.Action)).Distinct().Count());

        var byRisk = _catalog.Actions.GroupBy(definition => ActionRiskClassifier.Classify(definition.Effects)).ToDictionary(group => group.Key, group => group.Count());
        Assert.Equal(new Dictionary<RiskLevel, int> { [RiskLevel.Low] = 5, [RiskLevel.Medium] = 3, [RiskLevel.High] = 4, [RiskLevel.Critical] = 4 }, byRisk);
    }

    [Fact]
    public void Capabilities_AreExactlyTheRequiredOnes()
    {
        Assert.Equal(_catalog.Actions.Select(definition => definition.RequiredCapability).ToHashSet(), _catalog.Capabilities);
        Assert.Equal(15, _catalog.Capabilities.Count);
    }

    [Fact]
    public void ATool_IsNotAUnitOfPermission_ItsActionsHaveDifferentCapabilitiesAndRisks()
    {
        var email = _catalog.Actions.Where(definition => definition.Tool == new ToolId("email")).ToArray();

        Assert.Equal(3, email.Select(definition => definition.RequiredCapability).Distinct().Count());
        Assert.Equal([RiskLevel.Low, RiskLevel.Medium, RiskLevel.High], email.Select(definition => ActionRiskClassifier.Classify(definition.Effects)).Order());
    }

    [Fact]
    public void OneCapability_CanAuthoriseSeveralActions_OfTheSameRisk()
    {
        var dataRead = _catalog.Actions.Where(definition => definition.RequiredCapability == new Capability("data:read")).ToArray();

        Assert.Equal(["describe", "read"], dataRead.Select(definition => definition.Action.Value).Order(StringComparer.Ordinal));
        Assert.All(dataRead, definition => Assert.Equal(RiskLevel.Low, ActionRiskClassifier.Classify(definition.Effects)));
    }

    [Theory]
    [InlineData("shell", "exec")]
    [InlineData("email", "delete")]
    [InlineData("email", "forward")]
    [InlineData("payment", "refund")]
    [InlineData("data", "read-all")]
    [InlineData("datas", "read")]
    public void Find_UncataloguedActionOrTool_IsNull(string tool, string action)
    {
        Assert.Null(_catalog.Find(new ToolId(tool), new ActionName(action)));
    }

    [Fact]
    public void HasTool_IsTrueOnlyForToolsWithACataloguedAction()
    {
        Assert.All(["data", "email", "file", "browser", "customer", "payment", "secrets", "identity"], tool => Assert.True(_catalog.HasTool(new ToolId(tool))));
        Assert.All(["shell", "mcp", "emails", "data.read"], tool => Assert.False(_catalog.HasTool(new ToolId(tool))));
    }

    [Fact]
    public void Lookups_WithAMissingName_Throw_RatherThanAnswerUnknown()
    {
        // Mutation testing (M10): without the guards a null name read as "unknown"; the contract is that it is a bug.
        Assert.Throws<ArgumentNullException>(() => _catalog.HasTool(null!));
        Assert.Throws<ArgumentNullException>(() => _catalog.Find(null!, new ActionName("read")));
        Assert.Throws<ArgumentNullException>(() => _catalog.Find(new ToolId("data"), null!));
    }

    [Fact]
    public void Actions_CannotBeChangedThroughTheExposedCollection()
    {
        Assert.False(_catalog.Actions is ToolActionDefinition[]);
        var asList = Assert.IsAssignableFrom<IList<ToolActionDefinition>>(_catalog.Actions);
        Assert.True(asList.IsReadOnly);
        Assert.Throws<NotSupportedException>(() => { asList[0] = asList[^1]; });
    }
}
