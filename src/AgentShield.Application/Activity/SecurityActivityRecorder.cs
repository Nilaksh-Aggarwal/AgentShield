using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Activity;

/// <summary>
/// Records every published security event in the activity history, reduced to <see cref="SecurityActivityRecord"/>.
/// </summary>
/// <remarks>
/// One of the security-event sinks the analysis publishes to after the policy engine decided (next to the audit log). It
/// sees only the finished event, so it cannot influence the decision; if the store fails, the failure propagates and the
/// analysis fails closed (no decision is returned), as for any sink. Scoped, so a future store that needs a unit of work
/// (for example a <c>DbContext</c>) can replace the in-memory one without a lifetime change.
/// </remarks>
internal sealed class SecurityActivityRecorder(ISecurityActivityStore store) : ISecurityEventSink, IScopedService
{
    public ValueTask PublishAsync(SecurityEvent securityEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        return store.AppendAsync(SecurityActivityRecord.FromSecurityEvent(securityEvent), cancellationToken);
    }
}
