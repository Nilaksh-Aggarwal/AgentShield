namespace AgentShield.Application.Abstractions.Caching;

/// <summary>
/// Application-level cache. Application code depends on this abstraction, never on
/// <c>IMemoryCache</c> directly, so the backing store can later become distributed without
/// touching use cases.
/// </summary>
/// <remarks>
/// Asynchronous by design (a distributed implementation performs I/O). Cached values should be
/// immutable and serialisable. Never cache secrets or raw untrusted input keyed by user-controlled
/// strings without normalising and bounding the key.
/// </remarks>
public interface ICacheService
{
    /// <summary>Returns the cached value, or <see langword="null"/> when the key is not present.</summary>
    ValueTask<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default)
        where T : class;

    ValueTask SetAsync<T>(string key, T value, CacheEntrySettings? settings = null, CancellationToken cancellationToken = default);

    /// <summary>
    /// Returns the cached value, or invokes <paramref name="factory"/>, caches and returns its result.
    /// </summary>
    ValueTask<T> GetOrCreateAsync<T>(
        string key,
        Func<CancellationToken, ValueTask<T>> factory,
        CacheEntrySettings? settings = null,
        CancellationToken cancellationToken = default);

    ValueTask RemoveAsync(string key, CancellationToken cancellationToken = default);
}

/// <summary>Per-entry expiration. When omitted, the configured default expiration applies.</summary>
public sealed record CacheEntrySettings(TimeSpan? AbsoluteExpirationRelativeToNow = null, TimeSpan? SlidingExpiration = null);
