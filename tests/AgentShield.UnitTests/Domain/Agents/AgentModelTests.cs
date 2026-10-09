using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;

namespace AgentShield.UnitTests.Domain.Agents;

/// <summary>
/// The agent action domain model: trusted definitions that cannot be changed after they are built, untrusted proposals
/// that cannot carry undefined values, and a verdict whose decision cannot disagree with its reason.
/// </summary>
public sealed class AgentModelTests
{
    private static readonly AgentId Agent = new("support-agent");
    private static readonly ToolId Email = new("email");
    private static readonly ActionName Send = new("send");
    private static readonly Capability EmailSend = new("email:send");

    private const string Runtime = "support-runtime";

    private static readonly RecognisedAgentAction Complete = new(Agent, Email, Send, EmailSend);

    // ── Agent profile ───────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AgentProfile_HoldsExactlyTheGrantedCapabilities()
    {
        var profile = new AgentProfile(Agent, [new Capability("email:read"), EmailSend], [Runtime]);

        Assert.True(profile.Holds(new Capability("email:send")));
        Assert.True(profile.Holds(new Capability("email:read")));
        Assert.False(profile.Holds(new Capability("email:draft")));
        Assert.False(profile.Holds(new Capability("data:read")));
    }

    [Fact]
    public void AgentProfile_CopiesItsGrants_SoChangingTheSourceLaterGrantsNothing()
    {
        var source = new List<Capability> { new("data:read") };
        var profile = new AgentProfile(Agent, source, [Runtime]);

        source.Add(new Capability("payment:execute"));

        Assert.False(profile.Holds(new Capability("payment:execute")));
        Assert.Equal([new Capability("data:read")], profile.Capabilities);
    }

    [Fact]
    public void AgentProfile_Capabilities_CannotBeAddedToThroughTheExposedSet()
    {
        var profile = new AgentProfile(Agent, [new Capability("data:read")], [Runtime]);

        var asCollection = Assert.IsAssignableFrom<ICollection<Capability>>(profile.Capabilities);
        Assert.True(asCollection.IsReadOnly);
        Assert.Throws<NotSupportedException>(() => asCollection.Add(new Capability("payment:execute")));
        Assert.False(profile.Holds(new Capability("payment:execute")));
    }

    [Fact]
    public void AgentProfile_NullsAreRejected()
    {
        Assert.Throws<ArgumentNullException>(() => new AgentProfile(null!, [], [Runtime]));
        Assert.Throws<ArgumentNullException>(() => new AgentProfile(Agent, null!, [Runtime]));
        Assert.Throws<ArgumentNullException>(() => new AgentProfile(Agent, [], null!));
        Assert.Throws<ArgumentException>(() => new AgentProfile(Agent, [EmailSend, null!], [Runtime]));
        Assert.Throws<ArgumentException>(() => new AgentProfile(Agent, [EmailSend], [Runtime, " "]));
        Assert.Throws<ArgumentNullException>(() => new AgentProfile(Agent, [], [Runtime]).Holds(null!));
        Assert.Throws<ArgumentNullException>(() => new AgentProfile(Agent, [], [Runtime]).AcceptsCaller(null!));
    }

    [Fact]
    public void AgentProfile_AcceptsExactlyTheBoundCallers()
    {
        var profile = new AgentProfile(Agent, [EmailSend], [Runtime, "backup-runtime"]);

        Assert.True(profile.AcceptsCaller(Runtime));
        Assert.True(profile.AcceptsCaller("backup-runtime"));
        Assert.False(profile.AcceptsCaller("other-runtime"));
        Assert.False(profile.AcceptsCaller("Support-Runtime"));
        Assert.False(profile.AcceptsCaller(Runtime + " "));
        Assert.False(new AgentProfile(Agent, [EmailSend], []).AcceptsCaller(Runtime));
    }

    [Fact]
    public void AgentProfile_CopiesItsCallers_SoChangingTheSourceLaterBindsNoOne()
    {
        var source = new List<string> { Runtime };
        var profile = new AgentProfile(Agent, [EmailSend], source);

        source.Add("rogue-runtime");

        Assert.False(profile.AcceptsCaller("rogue-runtime"));
        var asCollection = Assert.IsAssignableFrom<ICollection<string>>(profile.Callers);
        Assert.Throws<NotSupportedException>(() => asCollection.Add("rogue-runtime"));
    }

    // ── Tool action definition ──────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void ToolActionDefinition_WithoutEffects_IsRejected_BecauseUnclassifiedIsNotSafe()
    {
        Assert.Throws<ArgumentException>(() => new ToolActionDefinition(Email, Send, EmailSend, ActionEffects.None));
    }

    [Theory]
    [InlineData(1 << 11)]
    [InlineData((1 << 11) | 1)]
    [InlineData(int.MinValue)]
    public void ToolActionDefinition_UnknownEffectBits_AreRejected(int effects)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new ToolActionDefinition(Email, Send, EmailSend, (ActionEffects)effects));
    }

    [Fact]
    public void ToolActionDefinition_AllEffects_IsEveryDeclaredEffect()
    {
        var declared = Enum.GetValues<ActionEffects>().Aggregate(ActionEffects.None, (all, effect) => all | effect);

        Assert.Equal(ToolActionDefinition.AllEffects, declared);
        Assert.Equal(11, Enum.GetValues<ActionEffects>().Count(effect => effect != ActionEffects.None));
    }

    [Fact]
    public void ToolActionDefinition_KeepsWhatItWasGiven()
    {
        var definition = new ToolActionDefinition(Email, Send, EmailSend, ActionEffects.ExternalCommunication | ActionEffects.ModifiesData);

        Assert.Equal((Email, Send, EmailSend), (definition.Tool, definition.Action, definition.RequiredCapability));
        Assert.Equal(ActionEffects.ExternalCommunication | ActionEffects.ModifiesData, definition.Effects);
        Assert.Throws<ArgumentNullException>(() => new ToolActionDefinition(null!, Send, EmailSend, ActionEffects.ReadOnly));
        Assert.Throws<ArgumentNullException>(() => new ToolActionDefinition(Email, null!, EmailSend, ActionEffects.ReadOnly));
        Assert.Throws<ArgumentNullException>(() => new ToolActionDefinition(Email, Send, null!, ActionEffects.ReadOnly));
    }

    // ── Reasons and decisions ───────────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(AgentActionReason.Permitted, SecurityDecision.Allow)]
    [InlineData(AgentActionReason.HumanApprovalRequired, SecurityDecision.Review)]
    [InlineData(AgentActionReason.InputHeldForReview, SecurityDecision.Review)]
    [InlineData(AgentActionReason.UnknownAgent, SecurityDecision.Block)]
    [InlineData(AgentActionReason.UnknownTool, SecurityDecision.Block)]
    [InlineData(AgentActionReason.UnknownAction, SecurityDecision.Block)]
    [InlineData(AgentActionReason.CapabilityMismatch, SecurityDecision.Block)]
    [InlineData(AgentActionReason.CapabilityNotGranted, SecurityDecision.Block)]
    [InlineData(AgentActionReason.CriticalActionDenied, SecurityDecision.Block)]
    [InlineData(AgentActionReason.InputBlocked, SecurityDecision.Block)]
    [InlineData(AgentActionReason.CallerNotBoundToAgent, SecurityDecision.Block)]
    public void DecisionFor_EachReason_HasExactlyOneDecision(AgentActionReason reason, SecurityDecision expected)
    {
        Assert.Equal(expected, AgentActionReasons.DecisionFor(reason));
    }

    [Fact]
    public void DecisionFor_OnlyPermittedAllows_AndEveryReasonIsCovered()
    {
        var reasons = Enum.GetValues<AgentActionReason>();

        Assert.Equal(11, reasons.Length);
        Assert.Equal([AgentActionReason.Permitted], reasons.Where(reason => AgentActionReasons.DecisionFor(reason) == SecurityDecision.Allow));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(12)]
    [InlineData(-1)]
    public void DecisionFor_UndefinedReason_Throws_NeverAllows(int reason)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => AgentActionReasons.DecisionFor((AgentActionReason)reason));
    }

    // ── Verdict ─────────────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Authorization_DecisionIsDerivedFromTheReason_ForEveryReason()
    {
        foreach (var reason in Enum.GetValues<AgentActionReason>())
        {
            var authorization = new AgentActionAuthorization(reason, RiskLevel.Low, RecognisedFor(reason));

            Assert.Equal(AgentActionReasons.DecisionFor(reason), authorization.Decision);
            Assert.Equal(reason, authorization.Reason);
        }
    }

    [Theory]
    [InlineData(AgentActionReason.Permitted)]
    [InlineData(AgentActionReason.HumanApprovalRequired)]
    [InlineData(AgentActionReason.InputHeldForReview)]
    public void Authorization_AllowOrReview_RequiresEveryIdentifierRecognised(AgentActionReason reason)
    {
        RecognisedAgentAction[] incomplete =
        [
            new(null, Email, Send, EmailSend),
            new(Agent, null, null, EmailSend),
            new(Agent, Email, null, EmailSend),
            new(Agent, Email, Send, null),
            new(null, null, null, null),
        ];

        Assert.All(incomplete, recognised => Assert.Throws<ArgumentException>(() => new AgentActionAuthorization(reason, RiskLevel.Low, recognised)));
    }

    [Fact]
    public void Authorization_BlockReasons_AcceptAnIncompleteRequest()
    {
        var authorization = new AgentActionAuthorization(AgentActionReason.CapabilityMismatch, RiskLevel.High, new RecognisedAgentAction(Agent, Email, Send, null));

        Assert.Equal(SecurityDecision.Block, authorization.Decision);
    }

    [Fact]
    public void Authorization_AReasonThatNamesSomethingUnknown_CannotCarryItAsRecognised()
    {
        Assert.Throws<ArgumentException>(() => new AgentActionAuthorization(AgentActionReason.UnknownAgent, RiskLevel.Low, Complete));
        Assert.Throws<ArgumentException>(() => new AgentActionAuthorization(AgentActionReason.UnknownTool, RiskLevel.Critical, new RecognisedAgentAction(Agent, Email, null, null)));
        Assert.Throws<ArgumentException>(() => new AgentActionAuthorization(AgentActionReason.UnknownAction, RiskLevel.Critical, new RecognisedAgentAction(Agent, Email, Send, null)));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    public void Authorization_UndefinedRisk_IsRejected(int risk)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgentActionAuthorization(AgentActionReason.Permitted, (RiskLevel)risk, Complete));
    }

    [Fact]
    public void Authorization_UndefinedReason_IsRejected()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgentActionAuthorization((AgentActionReason)0, RiskLevel.Low, Complete));
        Assert.Throws<ArgumentNullException>(() => new AgentActionAuthorization(AgentActionReason.Permitted, RiskLevel.Low, null!));
    }

    [Fact]
    public void RecognisedAgentAction_AnActionOfAnUnrecognisedTool_IsRejected()
    {
        Assert.Throws<ArgumentException>(() => new RecognisedAgentAction(Agent, null, Send, EmailSend));
        Assert.True(Complete.IsComplete);
        Assert.False(new RecognisedAgentAction(Agent, Email, Send, null).IsComplete);
    }

    // ── Proposal ────────────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void AgentActionRequest_RejectsMissingPartsAndUndefinedInputDecisions()
    {
        Assert.ThrowsAny<ArgumentException>(() => new AgentActionRequest(null!, Agent, Email, Send, EmailSend, null));
        Assert.ThrowsAny<ArgumentException>(() => new AgentActionRequest(" ", Agent, Email, Send, EmailSend, null));
        Assert.Throws<ArgumentNullException>(() => new AgentActionRequest(Runtime, null!, Email, Send, EmailSend, null));
        Assert.Throws<ArgumentNullException>(() => new AgentActionRequest(Runtime, Agent, null!, Send, EmailSend, null));
        Assert.Throws<ArgumentNullException>(() => new AgentActionRequest(Runtime, Agent, Email, null!, EmailSend, null));
        Assert.Throws<ArgumentNullException>(() => new AgentActionRequest(Runtime, Agent, Email, Send, null!, null));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgentActionRequest(Runtime, Agent, Email, Send, EmailSend, (SecurityDecision)0));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AgentActionRequest(Runtime, Agent, Email, Send, EmailSend, (SecurityDecision)4));

        var request = new AgentActionRequest(Runtime, Agent, Email, Send, EmailSend, SecurityDecision.Review);
        Assert.Equal(Runtime, request.Caller);
        Assert.Equal((Agent, Email, Send, EmailSend, SecurityDecision.Review), (request.Agent, request.Tool, request.Action, request.Capability, request.InputDecision));
    }

    private static RecognisedAgentAction RecognisedFor(AgentActionReason reason) => reason switch
    {
        AgentActionReason.UnknownAgent => new RecognisedAgentAction(null, Email, Send, EmailSend),
        AgentActionReason.UnknownTool => new RecognisedAgentAction(Agent, null, null, EmailSend),
        AgentActionReason.UnknownAction => new RecognisedAgentAction(Agent, Email, null, EmailSend),
        _ => Complete,
    };
}
