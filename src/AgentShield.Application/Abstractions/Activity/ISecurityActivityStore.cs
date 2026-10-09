using AgentShield.Application.Activity;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;

namespace AgentShield.Application.Abstractions.Activity;

/// <summary>
/// The security activity history: recent <see cref="SecurityActivityRecord"/>s, newest first. A read model for the
/// console, filled from the security events the analysis publishes; it is not the audit trail (the security-event log is).
/// </summary>
/// <remarks>
/// Today an in-process, bounded store (Infrastructure, ADR 0019): not durable, per process. A persistent store can replace
/// it behind this port without changing the recorder or the query use case. Implementations keep only what they are
/// given, so a record never holds more than <see cref="SecurityActivityRecord"/> allows.
/// </remarks>
public interface ISecurityActivityStore
{
    /// <summary>Adds a record. A failure is not swallowed: the analysis that published the event then fails.</summary>
    ValueTask AppendAsync(SecurityActivityRecord record, CancellationToken cancellationToken);

    /// <summary>The records matching <paramref name="query"/>'s filters, newest first, and how many match in total.</summary>
    ValueTask<SecurityActivitySlice> QueryAsync(SecurityActivityQuery query, CancellationToken cancellationToken);
}

/// <summary>A filtered, bounded read of the activity history.</summary>
/// <param name="Decisions">Only records with one of these decisions; every decision when empty.</param>
/// <param name="MinRiskLevel">Only records at or above this risk level; every level when <see langword="null"/>.</param>
/// <param name="Skip">Matching records to skip, newest first (at least 0).</param>
/// <param name="Take">At most this many records (at least 1).</param>
public sealed record SecurityActivityQuery(IReadOnlySet<SecurityDecision> Decisions, RiskLevel? MinRiskLevel, int Skip, int Take)
{
    public IReadOnlySet<SecurityDecision> Decisions { get; } = Decisions ?? throw new ArgumentNullException(nameof(Decisions));

    public int Skip { get; } = Skip >= 0 ? Skip : throw new ArgumentOutOfRangeException(nameof(Skip), Skip, "Skip cannot be negative.");

    public int Take { get; } = Take >= 1 ? Take : throw new ArgumentOutOfRangeException(nameof(Take), Take, "Take must be at least 1.");
}

/// <param name="Records">The requested records, newest first.</param>
/// <param name="TotalCount">How many records match the filters, across all pages.</param>
public sealed record SecurityActivitySlice(IReadOnlyList<SecurityActivityRecord> Records, int TotalCount);
