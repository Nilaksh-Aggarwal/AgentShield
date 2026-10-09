using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Activity;

/// <summary>
/// Records every agent action authorization in the activity history, reduced to <see cref="SecurityActivityRecord"/>.
/// </summary>
/// <remarks>
/// The agent action counterpart of <see cref="SecurityActivityRecorder"/>: it sees only the finished event, so it cannot
/// influence the decision, and a store failure propagates so the authorization fails closed (no decision is returned).
/// </remarks>
internal sealed class AgentActionActivityRecorder(ISecurityActivityStore store) : IAgentActionEventSink, IScopedService
{
    public ValueTask PublishAsync(AgentActionEvent agentActionEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(agentActionEvent);
        return store.AppendAsync(SecurityActivityRecord.FromAgentActionEvent(agentActionEvent), cancellationToken);
    }
}
