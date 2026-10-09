using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Abstractions.Agents;

/// <summary>
/// Records the tool gateway's audit entries. Every registered sink receives every entry of a request, in order: today the
/// structured audit log (Infrastructure) and the activity history (Application, terminal entries only). A sink only
/// records; it cannot change the decision or the outcome.
/// </summary>
/// <remarks>
/// Same contract as the other security-event sinks, applied at every stage: a failure to record is not swallowed. Every
/// sink is still tried, then the request fails (HTTP 500, no decision, no result) before the gateway goes any further, so
/// a grant is never issued, and a tool never runs, without its entries having been recorded.
/// </remarks>
public interface IToolGatewayEventSink
{
    ValueTask PublishAsync(ToolGatewayEvent toolGatewayEvent, CancellationToken cancellationToken);
}
