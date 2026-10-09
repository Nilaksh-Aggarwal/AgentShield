using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Activity;

/// <summary>
/// Records every tool gateway request in the activity history: one <see cref="SecurityActivityRecord"/> from the request's
/// last audit entry. The earlier stages are the audit log's (their outcome is already in the last entry).
/// </summary>
/// <remarks>
/// The tool gateway counterpart of <see cref="AgentActionActivityRecorder"/>: it sees only finished entries, so it cannot
/// influence the decision, and a store failure propagates so the request fails closed (no decision, no result).
/// </remarks>
internal sealed class ToolGatewayActivityRecorder(ISecurityActivityStore store) : IToolGatewayEventSink, IScopedService
{
    public ValueTask PublishAsync(ToolGatewayEvent toolGatewayEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(toolGatewayEvent);
        return toolGatewayEvent.IsTerminal
            ? store.AppendAsync(SecurityActivityRecord.FromToolGatewayEvent(toolGatewayEvent), cancellationToken)
            : ValueTask.CompletedTask;
    }
}
