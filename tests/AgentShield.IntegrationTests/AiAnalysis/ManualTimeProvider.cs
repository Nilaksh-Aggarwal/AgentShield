namespace AgentShield.IntegrationTests.AiAnalysis;

/// <summary>
/// Time that moves only when told to, including one-shot timers (what <see cref="CancellationTokenSource"/> uses for a
/// timeout), so timeout tests are exact and never wait on the wall clock.
/// </summary>
internal sealed class ManualTimeProvider : TimeProvider
{
    private static readonly DateTimeOffset Start = new(2026, 9, 29, 12, 0, 0, TimeSpan.Zero);

    private readonly Lock _lock = new();
    private readonly List<ManualTimer> _timers = [];
    private long _ticks;

    public override long TimestampFrequency => TimeSpan.TicksPerSecond;

    public int PendingTimers
    {
        get
        {
            lock (_lock)
            {
                return _timers.Count;
            }
        }
    }

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

    private sealed class ManualTimer(ManualTimeProvider owner, TimerCallback callback, object? state) : ITimer
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
