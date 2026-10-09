using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Globalization;
using AgentShield.Application.Abstractions.Context;
using Microsoft.Extensions.Logging;

namespace AgentShield.UnitTests.Infrastructure.AiCapacity;

/// <summary>
/// Time that moves only when told to, including one-shot timers (what <see cref="CancellationTokenSource"/> uses for the
/// AI stage's timeout), so window and timeout tests are exact and never wait on the wall clock. Starts one minute before
/// UTC midnight, so tests can show that nothing resets on a calendar boundary.
/// </summary>
internal sealed class ManualClock : TimeProvider
{
    public static readonly DateTimeOffset Start = new(2026, 9, 30, 23, 59, 0, TimeSpan.Zero);

    private readonly Lock _lock = new();
    private readonly List<ManualTimer> _timers = [];
    private long _ticks;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public override long GetTimestamp()
    {
        lock (_lock)
        {
            return _ticks;
        }
    }

    public override DateTimeOffset GetUtcNow() => Start.AddTicks(GetTimestamp());

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = new ManualTimer(this, callback, state);
        timer.Change(dueTime, period);
        return timer;
    }

    /// <summary>Moves time forward and fires every timer that became due (outside the lock).</summary>
    public void Advance(TimeSpan by)
    {
        ManualTimer[] due;
        lock (_lock)
        {
            _ticks += by.Ticks;
            due = [.. _timers.Where(timer => timer.DueAt <= _ticks)];
            _timers.RemoveAll(timer => timer.DueAt <= _ticks);
        }

        foreach (var timer in due)
        {
            timer.Fire();
        }
    }

    private sealed class ManualTimer(ManualClock owner, TimerCallback callback, object? state) : ITimer
    {
        public long DueAt { get; private set; }

        public bool Change(TimeSpan dueTime, TimeSpan period)
        {
            if (period != Timeout.InfiniteTimeSpan)
            {
                throw new NotSupportedException("Only one-shot timers are supported.");
            }

            lock (owner._lock)
            {
                owner._timers.Remove(this);
                if (dueTime != Timeout.InfiniteTimeSpan)
                {
                    DueAt = owner._ticks + dueTime.Ticks;
                    owner._timers.Add(this);
                }
            }

            return true;
        }

        public void Fire() => callback(state);

        public void Dispose()
        {
            lock (owner._lock)
            {
                owner._timers.Remove(this);
            }
        }

        public ValueTask DisposeAsync()
        {
            Dispose();
            return ValueTask.CompletedTask;
        }
    }
}

/// <summary>
/// Creates meters scoped to this factory, so a <see cref="MeterListener"/> can observe exactly one gate's instruments
/// while other tests run in parallel.
/// </summary>
internal sealed class TestMeterFactory : IMeterFactory
{
    private readonly ConcurrentBag<Meter> _meters = [];

    public Meter Create(MeterOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        var meter = new Meter(options.Name, options.Version, options.Tags, scope: this);
        _meters.Add(meter);
        return meter;
    }

    /// <summary>Counts every measurement of <paramref name="instrument"/> from this factory's meters, by the value of <paramref name="tag"/>.</summary>
    public MeasurementRecorder Record(string instrument, string tag) => new(this, instrument, tag);

    /// <summary>
    /// A metrics listener that fails on the first <paramref name="times"/> measurements of <paramref name="instrument"/> (a
    /// broken exporter): the exception reaches the code that records the measurement, as <see cref="MeterListener"/>
    /// callbacks run inline.
    /// </summary>
    public IDisposable ThrowOn(string instrument, int times = int.MaxValue)
    {
        var remaining = times;
        var listener = new MeterListener
        {
            InstrumentPublished = (published, listener) =>
            {
                if (ReferenceEquals(published.Meter.Scope, this) && published.Name == instrument)
                {
                    listener.EnableMeasurementEvents(published);
                }
            },
        };
        listener.SetMeasurementEventCallback<long>((_, _, _, _) =>
        {
            if (Interlocked.Decrement(ref remaining) >= 0)
            {
                throw new InvalidOperationException("Metrics listener failure.");
            }
        });
        listener.Start();
        return listener;
    }

    public void Dispose()
    {
        foreach (var meter in _meters)
        {
            meter.Dispose();
        }
    }

    internal sealed class MeasurementRecorder : IDisposable
    {
        private readonly MeterListener _listener = new();
        private readonly ConcurrentQueue<(string? Value, string[] TagKeys)> _measurements = new();

        public MeasurementRecorder(TestMeterFactory factory, string instrument, string tag)
        {
            _listener.InstrumentPublished = (published, listener) =>
            {
                if (ReferenceEquals(published.Meter.Scope, factory) && published.Name == instrument)
                {
                    listener.EnableMeasurementEvents(published);
                }
            };
            _listener.SetMeasurementEventCallback<long>((_, value, tags, _) =>
            {
                string? tagValue = null;
                var keys = new string[tags.Length];
                for (var index = 0; index < tags.Length; index++)
                {
                    keys[index] = tags[index].Key;
                    if (tags[index].Key == tag)
                    {
                        tagValue = Convert.ToString(tags[index].Value, CultureInfo.InvariantCulture);
                    }
                }

                for (var count = 0; count < value; count++)
                {
                    _measurements.Enqueue((tagValue, keys));
                }
            });
            _listener.Start();
        }

        public IReadOnlyDictionary<string, int> CountsByTag() =>
            _measurements.GroupBy(measurement => measurement.Value ?? "(none)").ToDictionary(group => group.Key, group => group.Count());

        public IEnumerable<string> TagKeys() => _measurements.SelectMany(measurement => measurement.TagKeys).Distinct();

        public void Dispose() => _listener.Dispose();
    }
}

/// <summary>Captures every log entry: level, event, rendered message and structured properties.</summary>
internal sealed class RecordingLogger<T> : ILogger<T>
{
    public ConcurrentQueue<Entry> Entries { get; } = new();

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        var properties = state is IEnumerable<KeyValuePair<string, object?>> pairs
            ? pairs.ToDictionary(pair => pair.Key, pair => Convert.ToString(pair.Value, CultureInfo.InvariantCulture), StringComparer.Ordinal)
            : [];
        Entries.Enqueue(new Entry(logLevel, eventId, formatter(state, exception), properties));
    }

    /// <summary>Everything an entry would put in a log sink, as one string, for leak checks.</summary>
    public string AllText() => string.Concat(Entries.Select(entry => entry.Message + string.Concat(entry.Properties.Values)));

    internal sealed record Entry(LogLevel Level, EventId EventId, string Message, IReadOnlyDictionary<string, string?> Properties);
}

/// <summary>A fixed set of configured analysis clients.</summary>
internal sealed class StaticClientDirectory(params string[] clientIds) : IApiClientDirectory
{
    public IReadOnlySet<string> AnalysisClientIds { get; } = clientIds.ToHashSet(StringComparer.Ordinal);

    public IReadOnlySet<string> AgentAuthorizationClientIds { get; init; } = new HashSet<string>(StringComparer.Ordinal);

    public IReadOnlySet<string> ToolExecutionClientIds { get; init; } = new HashSet<string>(StringComparer.Ordinal);
}
