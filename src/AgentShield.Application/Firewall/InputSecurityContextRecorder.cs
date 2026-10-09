using AgentShield.Application.Abstractions.Context;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Firewall;

/// <summary>
/// Records every finished firewall analysis as an <see cref="InputSecurityContext"/>, so a tool call can reference the
/// server's decision on its input instead of reporting one. A security-event sink like the audit log and the activity history:
/// it receives the finished event and copies its identity, trace, client and decision, nothing else.
/// </summary>
internal sealed class InputSecurityContextRecorder(IInputSecurityContextStore store, ICallerContext callerContext) : ISecurityEventSink, IScopedService
{
    public ValueTask PublishAsync(SecurityEvent securityEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        // The client comes from authentication: only the client that submitted the input may later reference its analysis.
        var context = new InputSecurityContext(
            securityEvent.Id,
            securityEvent.CorrelationId,
            callerContext.ClientId,
            securityEvent.Decision.Decision,
            securityEvent.OccurredAt);
        return store.RecordAsync(context, cancellationToken);
    }
}
