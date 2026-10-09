namespace AgentShield.Api.RateLimiting;

/// <summary>
/// Request rate limits (section <c>RateLimiting</c>), one fixed window per client and policy. Validated at startup.
/// </summary>
public sealed class RateLimitingOptions
{
    public const string SectionName = "RateLimiting";

    public const int MaxPermitLimit = 100_000;

    public const int MaxWindowSeconds = 3_600;

    public const int MaxQueueLimit = 100;

    /// <summary>
    /// Off only in Development (for load experiments); any other environment refuses to start with it off, so rate
    /// limiting is never disabled silently.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>The firewall analysis endpoint (CPU-bound detection, optional paid AI call): the strict policy.</summary>
    public RateLimitPolicyOptions Firewall { get; set; } = new() { PermitLimit = 60, WindowSeconds = 60 };

    /// <summary>Every other endpoint (readiness, full health report, future endpoints) except liveness.</summary>
    public RateLimitPolicyOptions Standard { get; set; } = new() { PermitLimit = 300, WindowSeconds = 60 };
}

/// <summary>A fixed-window limit: <see cref="PermitLimit"/> requests per <see cref="WindowSeconds"/> per client.</summary>
public sealed class RateLimitPolicyOptions
{
    public int PermitLimit { get; set; }

    public int WindowSeconds { get; set; }

    /// <summary>
    /// Requests allowed to wait for the next window instead of being rejected. 0 (the default) rejects at once: a
    /// queued request holds a connection, which is itself a resource an attacker can exhaust.
    /// </summary>
    public int QueueLimit { get; set; }

    internal bool IsValid() =>
        PermitLimit is >= 1 and <= RateLimitingOptions.MaxPermitLimit
        && WindowSeconds is >= 1 and <= RateLimitingOptions.MaxWindowSeconds
        && QueueLimit is >= 0 and <= RateLimitingOptions.MaxQueueLimit;
}
