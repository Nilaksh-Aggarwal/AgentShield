using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Abstractions.Security;

/// <summary>
/// Records security events. Every registered sink receives each event after the policy engine decided: today the
/// structured audit log (Infrastructure) and the activity history (<c>SecurityActivityRecorder</c>, Application). A sink
/// only records; it cannot change the decision.
/// </summary>
/// <remarks>
/// A failure to record is not swallowed: every sink is still tried, then the analysis fails rather than returning a
/// decision that was never recorded (no decision, HTTP 500; never an Allow).
/// </remarks>
public interface ISecurityEventSink
{
    ValueTask PublishAsync(SecurityEvent securityEvent, CancellationToken cancellationToken);
}
