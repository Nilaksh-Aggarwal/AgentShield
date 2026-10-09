using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Abstractions.Agents;

/// <summary>
/// Records agent action authorizations. Every registered sink receives each event after the boundary decided: today the
/// structured audit log (Infrastructure) and the activity history (Application). A sink only records; it cannot change the
/// decision.
/// </summary>
/// <remarks>
/// Same contract as <see cref="Security.ISecurityEventSink"/>: a failure to record is not swallowed. Every sink is still
/// tried, then the authorization fails (HTTP 500, no decision) rather than returning a decision that was never recorded.
/// </remarks>
public interface IAgentActionEventSink
{
    ValueTask PublishAsync(AgentActionEvent agentActionEvent, CancellationToken cancellationToken);
}
