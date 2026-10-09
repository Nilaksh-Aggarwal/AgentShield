using AgentShield.Application.Abstractions.Agents;
using AgentShield.Domain.Agents;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.SecurityTests.ToolGateway;

/// <summary>
/// The approvals the execution authority can look up: a plain dictionary (the real, atomic store lives in Infrastructure and
/// is tested there). The authority only reads approvals; deciding and using them is not its job.
/// </summary>
internal sealed class TestApprovalStore : IToolApprovalStore
{
    private readonly Dictionary<Guid, ToolApproval> _approvals = [];

    public TimeSpan Lifetime { get; } = TimeSpan.FromMinutes(10);

    public void Add(ToolApproval approval) => _approvals[approval.Id] = approval;

    public void Put(ToolApproval approval) => _approvals[approval.Id] = approval;

    public ToolApproval? Find(Guid approvalId) => _approvals.GetValueOrDefault(approvalId);

    public IReadOnlyList<ToolApproval> Recent(int count) => [.. _approvals.Values.Take(count)];

    public ToolApprovalDecision TryBeginDecision(Guid approvalId, bool approve, string decidedBy, DateTimeOffset now) =>
        throw new NotSupportedException("The execution authority never decides approvals.");

    public void CompleteDecision(Guid approvalId) =>
        throw new NotSupportedException("The execution authority never decides approvals.");

    public ToolApprovalUse TryUse(Guid approvalId, ToolApprovalBinding presented, SecurityEventId usedBy, DateTimeOffset now) =>
        throw new NotSupportedException("The execution authority never uses approvals.");

    public void Revoke(Guid approvalId, DateTimeOffset now) =>
        throw new NotSupportedException("The execution authority never revokes approvals.");
}
