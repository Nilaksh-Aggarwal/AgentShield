namespace AgentShield.Infrastructure.Caching;

public sealed class CacheOptions
{
    public const string SectionName = "Cache";

    /// <summary>Expiration applied when a caller does not specify one.</summary>
    public TimeSpan DefaultExpiration { get; set; } = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Maximum number of entries held in memory. Every entry has size 1, so this bounds memory use
    /// and prevents cache flooding from untrusted input.
    /// </summary>
    public long SizeLimit { get; set; } = 10_000;
}
