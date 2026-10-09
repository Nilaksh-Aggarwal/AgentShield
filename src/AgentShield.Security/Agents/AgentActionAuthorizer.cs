using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.Agents;

namespace AgentShield.Security.Agents;

/// <summary>
/// The agent action authorization boundary: establishes the facts about a request from AgentShield's own data (agent
/// directory, tool catalogue), classifies the action's risk from its declared effects, and lets the policy decide.
/// Deterministic, side-effect free, and it never executes anything.
/// </summary>
/// <remarks>
/// <para>The agent's claims are never trusted on their own: the agent must be bound to the authenticated caller, and the
/// capability that is checked is the one the catalogue requires, held only if the configured profile holds it; the claimed
/// capability must merely be equal to it. Identifiers are compared exactly, and an answer from the directory or catalogue
/// for another name than the one asked is ignored, so a lenient lookup in a future store cannot widen what matches.</para>
/// <para>Only names from AgentShield's own vocabulary are passed on for recording (<see cref="RecognisedAgentAction"/>).</para>
/// </remarks>
internal sealed class AgentActionAuthorizer(IToolCatalog catalog, IAgentDirectory directory) : IAgentActionAuthorizer, ISingletonService
{
    public AgentActionAuthorization Authorize(AgentActionRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        var profile = directory.Find(request.Agent) is { } found && found.Id == request.Agent ? found : null;
        var toolKnown = catalog.HasTool(request.Tool);
        var definition = toolKnown && catalog.Find(request.Tool, request.Action) is { } entry
            && entry.Tool == request.Tool && entry.Action == request.Action
                ? entry
                : null;

        var risk = definition is null ? ActionRiskClassifier.Unclassified : ActionRiskClassifier.Classify(definition.Effects);

        var reason = AgentActionPolicy.Decide(new AgentActionFacts(
            AgentKnown: profile is not null,
            CallerBound: profile is not null && profile.AcceptsCaller(request.Caller),
            ToolKnown: toolKnown,
            ActionKnown: definition is not null,
            CapabilityMatches: definition is not null && definition.RequiredCapability == request.Capability,
            CapabilityGranted: definition is not null && profile is not null && profile.Holds(definition.RequiredCapability),
            Risk: risk,
            InputDecision: request.InputDecision));

        var recognised = new RecognisedAgentAction(
            profile?.Id,
            toolKnown ? request.Tool : null,
            definition?.Action,
            catalog.Capabilities.Contains(request.Capability) ? request.Capability : null);

        return new AgentActionAuthorization(reason, risk, recognised);
    }
}
