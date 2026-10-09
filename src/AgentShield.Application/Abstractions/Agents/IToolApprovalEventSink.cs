using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Abstractions.Agents;

/// <summary>
/// Receives a person's decision on a held tool call (the audit log). Every sink gets the entry; when any fails, the decision is
/// withdrawn (the approval cannot authorise anything) and the request fails: an approval the audit log does not hold never
/// authorises an execution.
/// </summary>
public interface IToolApprovalEventSink
{
    ValueTask PublishAsync(ToolApprovalEvent toolApprovalEvent, CancellationToken cancellationToken);
}
