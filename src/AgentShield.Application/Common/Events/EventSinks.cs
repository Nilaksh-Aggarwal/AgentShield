using System.Runtime.ExceptionServices;

namespace AgentShield.Application.Common.Events;

/// <summary>
/// Gives an audit entry to every sink (audit log, activity history, ...) and only then raises what went wrong: the contract
/// every recording path shares (firewall analysis, agent action authorization, tool gateway, approvals).
/// </summary>
internal static class EventSinks
{
    /// <summary>
    /// Publishes <paramref name="value"/> to every sink. A sink that fails, or is cancelled, does not stop the others; once
    /// all were tried, a recording failure is raised (as itself, or as an aggregate of several), and otherwise a cancellation.
    /// So a cancelled request can never leave one sink holding an entry the others silently skipped.
    /// </summary>
    public static async Task PublishToEveryAsync<TSink, TEvent>(
        IEnumerable<TSink> sinks,
        TEvent value,
        Func<TSink, TEvent, CancellationToken, ValueTask> publish,
        string aggregateMessage,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(sinks);
        ArgumentNullException.ThrowIfNull(publish);

        List<Exception>? failures = null;
        OperationCanceledException? cancellation = null;
        foreach (var sink in sinks)
        {
            try
            {
                await publish(sink, value, cancellationToken);
            }
            catch (OperationCanceledException canceled)
            {
                cancellation ??= canceled;
            }
            catch (Exception exception)
            {
                (failures ??= []).Add(exception);
            }
        }

        if (failures is [var single])
        {
            ExceptionDispatchInfo.Throw(single);
        }

        if (failures is not null)
        {
            throw new AggregateException(aggregateMessage, failures);
        }

        if (cancellation is not null)
        {
            ExceptionDispatchInfo.Throw(cancellation);
        }
    }
}
