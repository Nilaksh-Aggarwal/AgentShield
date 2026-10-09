using AgentShield.Domain.Agents;

namespace AgentShield.Domain.SecurityEvents;

/// <summary>What happened to an approval. Its creation and its use are entries of the gateway request concerned.</summary>
public enum ToolApprovalEventType
{
    /// <summary>A person approved the held call: it may run once, until the approval expires.</summary>
    ToolApprovalApproved = 1,

    /// <summary>A person denied the held call: it will not run.</summary>
    ToolApprovalDenied = 2,
}

/// <summary>
/// One audit entry for a person's decision on a held tool call: the approval as it now stands (metadata only, never the
/// arguments or their digest), the decision, and the trace of the deciding request.
/// </summary>
public sealed record ToolApprovalEvent
{
    public ToolApprovalEvent(ToolApproval approval, string correlationId, DateTimeOffset occurredAt)
    {
        ArgumentNullException.ThrowIfNull(approval);
        ArgumentException.ThrowIfNullOrWhiteSpace(correlationId);

        Type = approval.Status switch
        {
            ToolApprovalStatus.Approved => ToolApprovalEventType.ToolApprovalApproved,
            ToolApprovalStatus.Denied => ToolApprovalEventType.ToolApprovalDenied,
            _ => throw new ArgumentException("Only an approval a person just approved or denied is recorded this way.", nameof(approval)),
        };

        if (approval.DecidedBy is null)
        {
            throw new ArgumentException("A decided approval names who decided it.", nameof(approval));
        }

        Approval = approval;
        CorrelationId = correlationId;
        OccurredAt = occurredAt;
    }

    public ToolApprovalEventType Type { get; }

    public ToolApproval Approval { get; }

    /// <summary>The trace of the request that decided (not the held request's trace, which the approval carries).</summary>
    public string CorrelationId { get; }

    public DateTimeOffset OccurredAt { get; }
}
