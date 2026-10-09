using AgentShield.Application.Abstractions.Caching;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace AgentShield.Infrastructure.Caching;

/// <summary>
/// In-process <see cref="ICacheService"/> backed by <see cref="IMemoryCache"/>.
/// </summary>
/// <remarks>
/// <see cref="GetOrCreateAsync{T}"/> does not coalesce concurrent misses for the same key; the factory
/// may run more than once under contention. Factories must therefore be idempotent.
/// </remarks>
internal sealed class MemoryCacheService(IMemoryCache cache, IOptions<CacheOptions> options) : ICacheService
{
    private readonly CacheOptions _options = options.Value;

    public ValueTask<T?> GetAsync<T>(string key, CancellationToken cancellationToken = default)
        where T : class
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        cancellationToken.ThrowIfCancellationRequested();

        return ValueTask.FromResult(cache.TryGetValue(key, out var value) ? value as T : null);
    }

    public ValueTask SetAsync<T>(string key, T value, CacheEntrySettings? settings = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(value);
        cancellationToken.ThrowIfCancellationRequested();

        cache.Set(key, value, CreateEntryOptions(settings));
        return ValueTask.CompletedTask;
    }

    public async ValueTask<T> GetOrCreateAsync<T>(
        string key,
        Func<CancellationToken, ValueTask<T>> factory,
        CacheEntrySettings? settings = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        ArgumentNullException.ThrowIfNull(factory);
        cancellationToken.ThrowIfCancellationRequested();

        if (cache.TryGetValue(key, out var cached) && cached is T hit)
        {
            return hit;
        }

        var created = await factory(cancellationToken);
        if (created is not null)
        {
            cache.Set(key, created, CreateEntryOptions(settings));
        }

        return created;
    }

    public ValueTask RemoveAsync(string key, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        cancellationToken.ThrowIfCancellationRequested();

        cache.Remove(key);
        return ValueTask.CompletedTask;
    }

    private MemoryCacheEntryOptions CreateEntryOptions(CacheEntrySettings? settings)
    {
        var absolute = settings?.AbsoluteExpirationRelativeToNow;
        var sliding = settings?.SlidingExpiration;

        return new MemoryCacheEntryOptions
        {
            // Fall back to the default absolute expiration only when the caller set no expiration at all.
            AbsoluteExpirationRelativeToNow = absolute ?? (sliding is null ? _options.DefaultExpiration : null),
            SlidingExpiration = sliding,
            Size = 1,
        };
    }
}
