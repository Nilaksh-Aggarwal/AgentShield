using AgentShield.Application.Abstractions.Caching;
using AgentShield.IntegrationTests.Infrastructure;
using Microsoft.Extensions.DependencyInjection;

namespace AgentShield.IntegrationTests.Caching;

public class MemoryCacheServiceTests(AgentShieldFactory factory) : IClassFixture<AgentShieldFactory>
{
    private readonly ICacheService _cache = factory.Services.GetRequiredService<ICacheService>();

    private static string NewKey() => $"test:{Guid.NewGuid():N}";

    private sealed record Payload(string Value);

    [Fact]
    public async Task SetThenGet_ReturnsStoredValue()
    {
        var key = NewKey();

        await _cache.SetAsync(key, new Payload("stored"));

        Assert.Equal(new Payload("stored"), await _cache.GetAsync<Payload>(key));
    }

    [Fact]
    public async Task Get_ReturnsNullForMissingKey()
    {
        Assert.Null(await _cache.GetAsync<Payload>(NewKey()));
    }

    [Fact]
    public async Task Remove_EvictsEntry()
    {
        var key = NewKey();
        await _cache.SetAsync(key, new Payload("x"));

        await _cache.RemoveAsync(key);

        Assert.Null(await _cache.GetAsync<Payload>(key));
    }

    [Fact]
    public async Task GetOrCreate_InvokesFactoryOnlyOnMiss()
    {
        var key = NewKey();
        var calls = 0;

        ValueTask<int> Factory(CancellationToken _) => ValueTask.FromResult(++calls);

        var first = await _cache.GetOrCreateAsync(key, Factory);
        var second = await _cache.GetOrCreateAsync(key, Factory);

        Assert.Equal(1, first);
        Assert.Equal(1, second);
        Assert.Equal(1, calls);
    }

    [Fact]
    public async Task ExpiredEntry_IsNotReturned()
    {
        var key = NewKey();

        await _cache.SetAsync(key, new Payload("short-lived"), new CacheEntrySettings(AbsoluteExpirationRelativeToNow: TimeSpan.FromMilliseconds(50)));
        await Task.Delay(TimeSpan.FromMilliseconds(200));

        Assert.Null(await _cache.GetAsync<Payload>(key));
    }

    [Fact]
    public async Task CancelledToken_IsHonoured()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(async () => await _cache.GetAsync<Payload>(NewKey(), cancellation.Token));
    }
}
