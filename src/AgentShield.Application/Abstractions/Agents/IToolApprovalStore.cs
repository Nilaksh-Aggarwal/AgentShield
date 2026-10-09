using AgentShield.Domain.Agents;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Abstractions.Agents;

/// <summary>
/// Holds the approvals of held tool calls, in memory and bounded, and changes them atomically: deciding and using an
/// approval each check and transition it under one lock, so exactly one of any number of concurrent attempts wins.
/// </summary>
/// <remarks>Per process and not durable, like execution grants: a restart forgets every approval (nothing can then run).</remarks>
public interface IToolApprovalStore
{
    /// <summary>How long an approval stays decidable and, once approved, usable.</summary>
    TimeSpan Lifetime { get; }

    /// <summary>Stores a new pending approval. Fails (rather than evicting a live approval) when too many are open.</summary>
    void Add(ToolApproval approval);

    ToolApproval? Find(Guid approvalId);

    /// <summary>The most recent approvals, newest first.</summary>
    IReadOnlyList<ToolApproval> Recent(int count);

    /// <summary>
    /// Begins deciding a pending, unexpired approval for <paramref name="decidedBy"/>: returns the approval as it will be once
    /// the decision takes effect, without letting it take effect yet. Until <see cref="CompleteDecision"/>, the stored approval
    /// stays pending (nothing can use it) and every other decision is refused as already decided. A decision is recorded in
    /// between, so it never takes effect unrecorded.
    /// </summary>
    ToolApprovalDecision TryBeginDecision(Guid approvalId, bool approve, string decidedBy, DateTimeOffset now);

    /// <summary>Makes the decision begun for <paramref name="approvalId"/> take effect. Fails if none was begun, or it was withdrawn since.</summary>
    void CompleteDecision(Guid approvalId);

    /// <summary>
    /// Uses an approved approval for gateway request <paramref name="usedBy"/>: only when it is approved, unused, unexpired
    /// and binds exactly <paramref name="presented"/>. After this it can never authorise anything again.
    /// </summary>
    ToolApprovalUse TryUse(Guid approvalId, ToolApprovalBinding presented, SecurityEventId usedBy, DateTimeOffset now);

    /// <summary>
    /// Withdraws an approval that could not be recorded (pending or approved → denied), so it never authorises anything; a
    /// decision begun for it can then never complete.
    /// </summary>
    void Revoke(Guid approvalId, DateTimeOffset now);
}

/// <summary>The result of deciding an approval: the decided approval, or why it could not be decided.</summary>
public sealed record ToolApprovalDecision(ToolApproval? Approval, ToolApprovalDecisionFailure? Failure)
{
    public static ToolApprovalDecision Decided(ToolApproval approval) => new(approval ?? throw new ArgumentNullException(nameof(approval)), null);

    public static ToolApprovalDecision Failed(ToolApprovalDecisionFailure failure) => new(null, failure);
}

public enum ToolApprovalDecisionFailure
{
    NotFound = 1,

    /// <summary>Already approved, denied or used, or being decided: an approval is decided once.</summary>
    AlreadyDecided = 2,

    Expired = 3,
}

/// <summary>The result of using an approval: the used approval, or why it does not authorise the call.</summary>
public sealed record ToolApprovalUse(ToolApproval? Approval, ToolApprovalRejection? Rejection)
{
    public static ToolApprovalUse Used(ToolApproval approval) => new(approval ?? throw new ArgumentNullException(nameof(approval)), null);

    public static ToolApprovalUse Rejected(ToolApprovalRejection rejection) => new(null, rejection);
}
