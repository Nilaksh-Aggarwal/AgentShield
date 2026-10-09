using AgentShield.Application.Abstractions.Security;
using AgentShield.Domain.Policy;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Infrastructure.Activity;
using AgentShield.UnitTests.Infrastructure.AiCapacity;

namespace AgentShield.UnitTests.Infrastructure.Activity;

/// <summary>The record of recent firewall decisions a tool call can reference (Milestone 13): bounded, expiring, metadata only.</summary>
public sealed class InMemoryInputSecurityContextStoreTests
{
    private readonly ManualClock _clock = new();

    [Fact]
    public async Task Record_ThenFind_ReturnsExactlyTheRecordedDecision()
    {
        var store = new InMemoryInputSecurityContextStore(_clock);
        var context = Context(SecurityDecision.Block);

        await store.RecordAsync(context, CancellationToken.None);

        Assert.Same(context, store.Find(context.SecurityEventId));
        Assert.Null(store.Find(SecurityEventId.New()));
    }

    [Fact]
    public async Task Record_DropsWhatHasExpired_AsNewAnalysesArrive()
    {
        var store = new InMemoryInputSecurityContextStore(_clock);
        var old = Context(SecurityDecision.Allow);
        await store.RecordAsync(old, CancellationToken.None);

        _clock.Advance(InputSecurityContext.Lifetime);
        var fresh = Context(SecurityDecision.Allow);
        await store.RecordAsync(fresh, CancellationToken.None);

        Assert.Null(store.Find(old.SecurityEventId));
        Assert.NotNull(store.Find(fresh.SecurityEventId));
    }

    [Fact]
    public async Task Record_BeyondTheBound_DropsTheOldest_SoAReferenceCanOnlyFail()
    {
        var store = new InMemoryInputSecurityContextStore(_clock);
        var first = Context(SecurityDecision.Allow);
        await store.RecordAsync(first, CancellationToken.None);
        for (var index = 1; index < InMemoryInputSecurityContextStore.Capacity; index++)
        {
            await store.RecordAsync(Context(SecurityDecision.Allow), CancellationToken.None);
        }

        var last = Context(SecurityDecision.Review);
        await store.RecordAsync(last, CancellationToken.None);

        Assert.Null(store.Find(first.SecurityEventId));
        Assert.Same(last, store.Find(last.SecurityEventId));
    }

    [Fact]
    public void Context_IsMetadataOnly_AndRefusesAnythingIncomplete()
    {
        Assert.Equal(
            ["Client", "CorrelationId", "Decision", "ExpiresAt", "OccurredAt", "SecurityEventId"],
            typeof(InputSecurityContext).GetProperties().Select(property => property.Name).Order(StringComparer.Ordinal));
        Assert.Throws<ArgumentException>(() => new InputSecurityContext(default, "corr", "client", SecurityDecision.Allow, _clock.GetUtcNow()));
        Assert.Throws<ArgumentException>(() => new InputSecurityContext(SecurityEventId.New(), " ", "client", SecurityDecision.Allow, _clock.GetUtcNow()));
        Assert.Throws<ArgumentException>(() => new InputSecurityContext(SecurityEventId.New(), "corr", "", SecurityDecision.Allow, _clock.GetUtcNow()));
        Assert.Throws<ArgumentOutOfRangeException>(() => new InputSecurityContext(SecurityEventId.New(), "corr", "client", (SecurityDecision)99, _clock.GetUtcNow()));
        Assert.Equal(TimeSpan.FromMinutes(10), InputSecurityContext.Lifetime);
    }

    private InputSecurityContext Context(SecurityDecision decision) =>
        new(SecurityEventId.New(), "corr-input", "support-runtime", decision, _clock.GetUtcNow());
}
