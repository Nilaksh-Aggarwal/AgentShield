using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Activity;

namespace AgentShield.Infrastructure.Activity;

/// <summary>
/// The activity history in process memory: the most recent <see cref="DefaultCapacity"/> records, the oldest dropped
/// first, returned newest first in the order they were recorded.
/// </summary>
/// <remarks>
/// <para>Not durable and not the audit trail: records are lost when the process stops, and each instance keeps its own.
/// The security-event log stays the audit record (ADR 0019).</para>
/// <para>Bounded in memory (a fixed ring of records, each holding only <see cref="SecurityActivityRecord"/> metadata)
/// and in work (a query reads at most <see cref="Capacity"/> records). Appends and reads take one short lock; filtering
/// runs on a copy outside it.</para>
/// </remarks>
internal sealed class InMemorySecurityActivityStore : ISecurityActivityStore, ISingletonService
{
    public const int DefaultCapacity = 1_000;

    private readonly Lock _lock = new();
    private readonly SecurityActivityRecord[] _ring;
    private int _next;
    private int _count;

    public InMemorySecurityActivityStore()
        : this(DefaultCapacity)
    {
    }

    /// <summary>A store of another size, for tests (the container uses the public constructor).</summary>
    internal InMemorySecurityActivityStore(int capacity)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _ring = new SecurityActivityRecord[capacity];
    }

    public int Capacity => _ring.Length;

    public ValueTask AppendAsync(SecurityActivityRecord record, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(record);

        lock (_lock)
        {
            _ring[_next] = record;
            _next = (_next + 1) % _ring.Length;
            _count = Math.Min(_count + 1, _ring.Length);
        }

        return ValueTask.CompletedTask;
    }

    public ValueTask<SecurityActivitySlice> QueryAsync(SecurityActivityQuery query, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(query);
        cancellationToken.ThrowIfCancellationRequested();

        var matching = Snapshot()
            .Where(record => query.Decisions.Count == 0 || query.Decisions.Contains(record.Decision))
            .Where(record => query.MinRiskLevel is not { } minimum || record.Risk.Level >= minimum)
            .ToArray();

        return ValueTask.FromResult(new SecurityActivitySlice([.. matching.Skip(query.Skip).Take(query.Take)], matching.Length));
    }

    // Newest first: walks the ring backwards from the last record written.
    private SecurityActivityRecord[] Snapshot()
    {
        lock (_lock)
        {
            var records = new SecurityActivityRecord[_count];
            for (var index = 0; index < _count; index++)
            {
                records[index] = _ring[(_next - 1 - index + _ring.Length) % _ring.Length];
            }

            return records;
        }
    }
}
