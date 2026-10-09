using AgentShield.Application.Abstractions.Agents;
using AgentShield.Domain.Agents;
using AgentShield.Domain.SecurityEvents;
using Microsoft.Extensions.Options;

namespace AgentShield.Infrastructure.Agents;

/// <summary>Configuration of held tool calls' approvals (section <c>ToolApprovals</c>).</summary>
public sealed class ToolApprovalOptions
{
    public const string SectionName = "ToolApprovals";

    /// <summary>How long an approval can be decided and, once approved, used (default 10 minutes).</summary>
    public int LifetimeSeconds { get; set; } = 600;
}

/// <summary>
/// Approvals in memory, bounded, per process. Every read-check-write happens under one lock, so of any number of concurrent
/// attempts to decide or use an approval exactly one wins. Finished approvals (denied, used, expired) make room for new ones;
/// open ones are never evicted: when the store is full of open approvals, adding fails (the request fails closed, nothing is
/// held without an approval record).
/// </summary>
internal sealed class InMemoryToolApprovalStore : IToolApprovalStore
{
    public const int Capacity = 1_000;

    private readonly Lock _lock = new();
    private readonly Dictionary<Guid, ToolApproval> _approvals = [];
    private readonly LinkedList<Guid> _order = new();

    // Decisions begun but not yet recorded: the decided approval waits here, so the stored one stays pending meanwhile.
    private readonly Dictionary<Guid, ToolApproval> _deciding = [];
    private readonly TimeProvider _timeProvider;

    public InMemoryToolApprovalStore(IOptions<ToolApprovalOptions> options, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);

        Lifetime = TimeSpan.FromSeconds(options.Value.LifetimeSeconds);
        _timeProvider = timeProvider;
    }

    public TimeSpan Lifetime { get; }

    public void Add(ToolApproval approval)
    {
        ArgumentNullException.ThrowIfNull(approval);

        lock (_lock)
        {
            if (_approvals.Count >= Capacity)
            {
                RemoveFinished(_timeProvider.GetUtcNow());
            }

            if (_approvals.Count >= Capacity)
            {
                throw new InvalidOperationException("Too many tool approvals are open.");
            }

            if (!_approvals.TryAdd(approval.Id, approval))
            {
                throw new InvalidOperationException("An approval ID was issued twice.");
            }

            _order.AddLast(approval.Id);
        }
    }

    public ToolApproval? Find(Guid approvalId)
    {
        lock (_lock)
        {
            return _approvals.GetValueOrDefault(approvalId);
        }
    }

    public IReadOnlyList<ToolApproval> Recent(int count)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(count);

        lock (_lock)
        {
            var recent = new List<ToolApproval>(Math.Min(count, _approvals.Count));
            for (var node = _order.Last; node is not null && recent.Count < count; node = node.Previous)
            {
                recent.Add(_approvals[node.Value]);
            }

            return recent;
        }
    }

    public ToolApprovalDecision TryBeginDecision(Guid approvalId, bool approve, string decidedBy, DateTimeOffset now)
    {
        lock (_lock)
        {
            if (!_approvals.TryGetValue(approvalId, out var approval))
            {
                return ToolApprovalDecision.Failed(ToolApprovalDecisionFailure.NotFound);
            }

            switch (approval.StatusAt(now))
            {
                case ToolApprovalStatus.Expired:
                    return ToolApprovalDecision.Failed(ToolApprovalDecisionFailure.Expired);
                case not ToolApprovalStatus.Pending:
                    return ToolApprovalDecision.Failed(ToolApprovalDecisionFailure.AlreadyDecided);
            }

            // Held here, not stored: the approval stays pending until the decision is recorded and completed.
            var decided = approve ? approval.Approve(now, decidedBy) : approval.Deny(now, decidedBy);
            return _deciding.TryAdd(approvalId, decided)
                ? ToolApprovalDecision.Decided(decided)
                : ToolApprovalDecision.Failed(ToolApprovalDecisionFailure.AlreadyDecided);
        }
    }

    public void CompleteDecision(Guid approvalId)
    {
        lock (_lock)
        {
            if (!_deciding.Remove(approvalId, out var decided))
            {
                throw new InvalidOperationException("No decision was begun for this approval, or it was withdrawn since.");
            }

            _approvals[approvalId] = decided;
        }
    }

    public ToolApprovalUse TryUse(Guid approvalId, ToolApprovalBinding presented, SecurityEventId usedBy, DateTimeOffset now)
    {
        ArgumentNullException.ThrowIfNull(presented);

        lock (_lock)
        {
            if (!_approvals.TryGetValue(approvalId, out var approval))
            {
                return ToolApprovalUse.Rejected(ToolApprovalRejection.NotFound);
            }

            if (approval.RejectionFor(presented, now) is { } rejection)
            {
                return ToolApprovalUse.Rejected(rejection);
            }

            var used = approval.Use(presented, now, usedBy);
            _approvals[approvalId] = used;
            return ToolApprovalUse.Used(used);
        }
    }

    public void Revoke(Guid approvalId, DateTimeOffset now)
    {
        lock (_lock)
        {
            _deciding.Remove(approvalId);
            if (_approvals.TryGetValue(approvalId, out var approval))
            {
                _approvals[approvalId] = approval.Revoke(now);
            }
        }
    }

    // Oldest first; only approvals that can never authorise anything again, and none with a decision being recorded.
    private void RemoveFinished(DateTimeOffset now)
    {
        for (var node = _order.First; node is not null;)
        {
            var next = node.Next;
            if (!_deciding.ContainsKey(node.Value)
                && _approvals[node.Value].StatusAt(now) is ToolApprovalStatus.Denied or ToolApprovalStatus.Used or ToolApprovalStatus.Expired)
            {
                _approvals.Remove(node.Value);
                _order.Remove(node);
            }

            node = next;
        }
    }
}
