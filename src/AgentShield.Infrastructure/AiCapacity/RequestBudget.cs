namespace AgentShield.Infrastructure.AiCapacity;

/// <summary>Where an admission would come from in one <see cref="RequestBudget"/>, or why it cannot.</summary>
internal enum BudgetShare
{
    /// <summary>From the client's reserved share.</summary>
    Guaranteed = 1,

    /// <summary>From the unreserved remainder, which the client may use above its guarantee.</summary>
    Shared = 2,

    /// <summary>The client's own maximum is reached.</summary>
    ClientLimitReached = 3,

    /// <summary>The global budget, less what is reserved for other clients, is spent.</summary>
    GlobalLimitReached = 4,
}

/// <summary>
/// One budget over a rolling window (a minute or a day) with per-client guaranteed and maximum shares. Each admission
/// carries an amount: 1 for request budgets, the reserved input-token estimate for the token budget. Not thread-safe:
/// <see cref="InMemoryAiCapacityGate"/> serialises access.
/// </summary>
/// <remarks>
/// <para><b>Window:</b> a sliding log. Every admission is timestamped (monotonic <see cref="TimeProvider"/> ticks) and
/// counts, with its amount, until exactly one window length later, so no rolling window ever holds more than the limit. A
/// fixed window (reset on the clock minute or at midnight) would allow twice the limit across a boundary, which could
/// exceed a provider quota the budget is meant to stay below. Memory is bounded by the number of admissions in a window.</para>
/// <para><b>Shares.</b> Invariant: <c>used + Σ unused guarantees of every client ≤ global limit</c>. It holds initially
/// when <c>clients × guaranteed ≤ global limit</c> (validated at startup) and is preserved by every step:</para>
/// <list type="bullet">
/// <item>An admission that fits in the client's unused guarantee comes from its reservation (used +a, its unused
/// guarantee −a).</item>
/// <item>Any other admission must fit in what is left after every other client's unused guarantee
/// (<c>used + a + Σ others' unused guarantees ≤ global</c>), so it can never take capacity reserved for another client,
/// including one that has not called yet.</item>
/// <item>No client exceeds its maximum; nothing exceeds the global limit.</item>
/// <item>An expiring admission lowers <c>used</c> by its amount and raises unused guarantees by at most that amount.</item>
/// </list>
/// For an amount of 1 these are exactly the rules of a request count.
/// </remarks>
internal sealed class RequestBudget
{
    private readonly long _window;
    private readonly long _globalLimit;
    private readonly long _guaranteed;
    private readonly long _clientLimit;
    private readonly Usage _all = new();
    private readonly Dictionary<string, Usage> _byClient;

    /// <param name="window">Window length in <see cref="TimeProvider"/> timestamp ticks.</param>
    /// <param name="globalLimit">Amount admitted per window, all clients together.</param>
    /// <param name="guaranteed">Amount per window reserved for each client.</param>
    /// <param name="clientLimit">Most amount per window for one client.</param>
    /// <param name="clientIds">Every client that holds a reservation.</param>
    public RequestBudget(long window, long globalLimit, long guaranteed, long clientLimit, IEnumerable<string> clientIds)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(window);
        ArgumentNullException.ThrowIfNull(clientIds);

        _window = window;
        _globalLimit = globalLimit;
        _guaranteed = guaranteed;
        _clientLimit = clientLimit;
        _byClient = clientIds.ToDictionary(id => id, _ => new Usage(), StringComparer.Ordinal);
    }

    /// <summary>Amount admitted in the window ending at the last <see cref="Check"/>, all clients together.</summary>
    public long Used => _all.Total;

    /// <summary>Whether <paramref name="amount"/> for <paramref name="clientId"/> (a known client) fits at <paramref name="now"/>.</summary>
    public BudgetShare Check(string clientId, long now, long amount = 1)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(amount);
        Expire(now);

        // Compared with the room left, never as a sum: an amount near long.MaxValue (a faulty token estimate) is refused
        // instead of wrapping round into an admission. Totals never exceed their limits, so no subtraction overflows.
        var own = _byClient[clientId].Total;
        if (amount > _clientLimit - own)
        {
            return BudgetShare.ClientLimitReached;
        }

        if (amount > _globalLimit - _all.Total)
        {
            return BudgetShare.GlobalLimitReached;
        }

        if (amount <= _guaranteed - own)
        {
            return BudgetShare.Guaranteed;
        }

        var reservedForOthers = 0L;
        foreach (var (id, usage) in _byClient)
        {
            if (!string.Equals(id, clientId, StringComparison.Ordinal))
            {
                reservedForOthers += Math.Max(0, _guaranteed - usage.Total);
            }
        }

        return amount <= _globalLimit - _all.Total - reservedForOthers ? BudgetShare.Shared : BudgetShare.GlobalLimitReached;
    }

    /// <summary>Counts <paramref name="amount"/> for <paramref name="clientId"/> at <paramref name="now"/> (after a successful check).</summary>
    public void Record(string clientId, long now, long amount = 1)
    {
        _all.Add(now, amount);
        _byClient[clientId].Add(now, amount);
    }

    private void Expire(long now)
    {
        _all.Expire(now, _window);
        foreach (var usage in _byClient.Values)
        {
            usage.Expire(now, _window);
        }
    }

    /// <summary>The admissions still inside the window and their total amount.</summary>
    private sealed class Usage
    {
        private readonly Queue<(long At, long Amount)> _entries = new();

        public long Total { get; private set; }

        public void Add(long at, long amount)
        {
            _entries.Enqueue((at, amount));
            Total += amount;
        }

        public void Expire(long now, long window)
        {
            while (_entries.TryPeek(out var entry) && now - entry.At >= window)
            {
                _entries.Dequeue();
                Total -= entry.Amount;
            }
        }
    }
}
