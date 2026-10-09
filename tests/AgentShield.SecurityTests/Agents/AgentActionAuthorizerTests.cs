using AgentShield.Application.Abstractions.Agents;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Security.Agents;
using static AgentShield.SecurityTests.Agents.AgentTestData;

namespace AgentShield.SecurityTests.Agents;

/// <summary>
/// The authorization boundary with the production reference catalogue: facts come only from AgentShield's own data, names
/// match exactly, a lenient or wrong lookup cannot widen what matches, and only recognised names are passed on.
/// </summary>
public sealed class AgentActionAuthorizerTests
{
    private static readonly SecurityDecision?[] InputDecisions = [null, SecurityDecision.Allow, SecurityDecision.Review, SecurityDecision.Block];

    [Fact]
    public void Authorize_EveryAgentAndCataloguedAction_HonestRequest_IsDecidedByGrantAndRisk()
    {
        var decided = 0;
        foreach (var profile in TestAgents.Profiles)
        {
            var caller = profile.Callers.Single();
            foreach (var definition in Catalog.Actions)
            {
                var authorization = Authorizer.Authorize(new AgentActionRequest(caller, profile.Id, definition.Tool, definition.Action, definition.RequiredCapability, null));

                var risk = ActionRiskClassifier.Classify(definition.Effects);
                var expected = !profile.Holds(definition.RequiredCapability) ? AgentActionReason.CapabilityNotGranted
                    : risk == RiskLevel.Critical ? AgentActionReason.CriticalActionDenied
                    : risk == RiskLevel.High ? AgentActionReason.HumanApprovalRequired
                    : AgentActionReason.Permitted;
                Assert.Equal((expected, risk), (authorization.Reason, authorization.Risk));
                Assert.Equal(new RecognisedAgentAction(profile.Id, definition.Tool, definition.Action, definition.RequiredCapability), authorization.Recognised);
                decided++;
            }
        }

        Assert.Equal(TestAgents.Profiles.Count * 16, decided);
    }

    [Fact]
    public void Authorize_NoClaimedCapabilityOrInputDecision_CanLowerTheHonestDecision()
    {
        // Everything the agent can vary for an action it wants (the capability it claims, the input decision it reports),
        // for every configured agent and every catalogued action: never below the honest request's decision.
        Capability[] claims = [.. Catalog.Capabilities, new("admin:all"), new("email:send-all"), new("root:root")];
        var combinations = 0;
        foreach (var profile in TestAgents.Profiles)
        {
            var caller = profile.Callers.Single();
            foreach (var definition in Catalog.Actions)
            {
                var honest = Authorizer.Authorize(new AgentActionRequest(caller, profile.Id, definition.Tool, definition.Action, definition.RequiredCapability, null)).Decision;
                foreach (var claim in claims)
                {
                    foreach (var input in InputDecisions)
                    {
                        var claimed = Authorizer.Authorize(new AgentActionRequest(caller, profile.Id, definition.Tool, definition.Action, claim, input)).Decision;

                        Assert.True(Rank(claimed) >= Rank(honest), $"{profile.Id}/{definition.Tool}.{definition.Action} claiming {claim} with input {input}: {claimed} < {honest}");
                        combinations++;
                    }
                }
            }
        }

        Assert.Equal(TestAgents.Profiles.Count * 16 * (Catalog.Capabilities.Count + 3) * InputDecisions.Length, combinations);
    }

    [Fact]
    public void Authorize_TheClaimedCapabilityGrantsNothing_OnlyTheProfileDoes()
    {
        // research-agent holds data:read but not data:write.
        Assert.Equal(AgentActionReason.CapabilityNotGranted, Authorize("research-agent", "data", "write", "data:write").Reason);
        Assert.Equal(AgentActionReason.CapabilityMismatch, Authorize("research-agent", "data", "write", "data:read").Reason);
        Assert.Equal(AgentActionReason.Permitted, Authorize("operations-agent", "data", "write", "data:write").Reason);
    }

    [Fact]
    public void Authorize_ACapabilityOfAnotherActionOfTheSameTool_DoesNotAuthorise()
    {
        // support-agent holds email:read and email:send; neither is the capability of the other action.
        Assert.Equal(AgentActionReason.CapabilityMismatch, Authorize("support-agent", "email", "send", "email:read").Reason);
        Assert.Equal(AgentActionReason.CapabilityMismatch, Authorize("support-agent", "email", "read", "email:send").Reason);
    }

    [Fact]
    public void Authorize_ACallerActingForAnAgentItIsNotBoundTo_IsBlocked()
    {
        var impersonation = Authorize("finance-agent", "data", "read", "data:read", caller: RuntimeA);
        var bound = Authorize("finance-agent", "data", "read", "data:read", caller: RuntimeB);
        var unknownCaller = Authorize("support-agent", "data", "read", "data:read", caller: "runtime-c");

        Assert.Equal((SecurityDecision.Block, AgentActionReason.CallerNotBoundToAgent), (impersonation.Decision, impersonation.Reason));
        Assert.Equal(SecurityDecision.Allow, bound.Decision);
        Assert.Equal(AgentActionReason.CallerNotBoundToAgent, unknownCaller.Reason);
        Assert.Equal(AgentActionReason.CallerNotBoundToAgent, Authorize("support-agent", "data", "read", "data:read", caller: "Runtime-A").Reason);
    }

    [Fact]
    public void Authorize_UnknownAgentToolOrAction_IsBlocked_AndAnUnclassifiableActionIsCritical()
    {
        var agent = Authorize("ghost-agent", "data", "read", "data:read");
        var tool = Authorize("support-agent", "shell", "exec", "shell:exec");
        var action = Authorize("support-agent", "email", "delete", "email:delete");

        Assert.Equal((SecurityDecision.Block, AgentActionReason.UnknownAgent, RiskLevel.Low), (agent.Decision, agent.Reason, agent.Risk));
        Assert.Equal((SecurityDecision.Block, AgentActionReason.UnknownTool, RiskLevel.Critical), (tool.Decision, tool.Reason, tool.Risk));
        Assert.Equal((SecurityDecision.Block, AgentActionReason.UnknownAction, RiskLevel.Critical), (action.Decision, action.Reason, action.Risk));
    }

    [Fact]
    public void Authorize_PassesOnOnlyNamesFromAgentShieldsOwnVocabulary()
    {
        var madeUp = Authorize("ghost-agent", "shell", "exec", "shell:exec");
        var unknownAction = Authorize("support-agent", "email", "delete", "email:send");
        var unknownCapability = Authorize("support-agent", "email", "send", "email:send-all");

        Assert.Equal(new RecognisedAgentAction(null, null, null, null), madeUp.Recognised);
        Assert.Equal(new RecognisedAgentAction(new AgentId("support-agent"), new ToolId("email"), null, new Capability("email:send")), unknownAction.Recognised);
        Assert.Equal(new RecognisedAgentAction(new AgentId("support-agent"), new ToolId("email"), new ActionName("send"), null), unknownCapability.Recognised);
    }

    [Fact]
    public void Authorize_ADirectoryAnsweringForAnotherAgent_IsNotTrusted()
    {
        var lenient = new LenientDirectory(new AgentProfile(new AgentId("finance-agent"), [new Capability("payment:execute"), new Capability("data:read")], [RuntimeA]));
        var authorizer = new AgentActionAuthorizer(Catalog, lenient);

        var authorization = authorizer.Authorize(Request("support-agent", "data", "read", "data:read"));

        Assert.Equal(AgentActionReason.UnknownAgent, authorization.Reason);
        Assert.Null(authorization.Recognised.Agent);
    }

    [Fact]
    public void Authorize_ACatalogueAnsweringForAnotherAction_IsNotTrusted()
    {
        // A catalogue that resolves any name to "data.read" (a lenient or buggy store) must not make "payment.execute" Low.
        var authorizer = new AgentActionAuthorizer(new LenientCatalog(Catalog.Find(new ToolId("data"), new ActionName("read"))!), TestAgents);

        var authorization = authorizer.Authorize(Request("finance-agent", "payment", "execute", "data:read", caller: RuntimeB));

        Assert.Equal((SecurityDecision.Block, AgentActionReason.UnknownAction, RiskLevel.Critical), (authorization.Decision, authorization.Reason, authorization.Risk));
    }

    [Fact]
    public void Authorize_IsDeterministic()
    {
        var first = Authorize("support-agent", "email", "send", "email:send", SecurityDecision.Allow);
        var second = Authorize("support-agent", "email", "send", "email:send", SecurityDecision.Allow);

        Assert.Equal(first, second);
    }

    [Fact]
    public void Authorize_NullRequest_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => Authorizer.Authorize(null!));
    }

    /// <summary>Returns its one profile for any agent ID.</summary>
    private sealed class LenientDirectory(AgentProfile profile) : IAgentDirectory
    {
        public AgentProfile? Find(AgentId agent) => profile;

        public AgentProfile? FindByGatewayClient(string clientId) => profile;
    }

    /// <summary>Knows every tool and resolves every action to the same definition.</summary>
    private sealed class LenientCatalog(ToolActionDefinition answer) : IToolCatalog
    {
        public IReadOnlyCollection<ToolActionDefinition> Actions { get; } = [answer];

        public IReadOnlySet<Capability> Capabilities { get; } = new HashSet<Capability> { answer.RequiredCapability };

        public bool HasTool(ToolId tool) => true;

        public ToolActionDefinition? Find(ToolId tool, ActionName action) => answer;
    }
}
