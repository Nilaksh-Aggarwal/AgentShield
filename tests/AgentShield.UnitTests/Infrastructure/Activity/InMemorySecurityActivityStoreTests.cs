using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Activity;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Infrastructure.Activity;
using static AgentShield.UnitTests.Application.Activity.ActivityTestEvents;

namespace AgentShield.UnitTests.Infrastructure.Activity;

public class InMemorySecurityActivityStoreTests
{
    private static readonly IReadOnlySet<SecurityDecision> AnyDecision = new HashSet<SecurityDecision>();

    [Fact]
    public async Task QueryAsync_Empty_ReturnsNoRecords()
    {
        var slice = await new InMemorySecurityActivityStore().QueryAsync(Query(), CancellationToken.None);

        Assert.Empty(slice.Records);
        Assert.Equal(0, slice.TotalCount);
    }

    [Fact]
    public async Task QueryAsync_ReturnsTheNewestRecordFirst()
    {
        var store = new InMemorySecurityActivityStore();
        await AppendAsync(store, Record(SecurityDecision.Allow, 0, "first"), Record(SecurityDecision.Block, 90, "second"), Record(SecurityDecision.Review, 40, "third"));

        var slice = await store.QueryAsync(Query(), CancellationToken.None);

        Assert.Equal(["third", "second", "first"], slice.Records.Select(record => record.CorrelationId));
        Assert.Equal(3, slice.TotalCount);
    }

    [Fact]
    public async Task AppendAsync_BeyondTheCapacity_DropsTheOldestRecords_SoMemoryStaysBounded()
    {
        var store = new InMemorySecurityActivityStore(capacity: 3);
        for (var index = 1; index <= 7; index++)
        {
            await store.AppendAsync(Record(SecurityDecision.Allow, 0, $"event-{index}"), CancellationToken.None);
        }

        var slice = await store.QueryAsync(Query(take: 100), CancellationToken.None);

        Assert.Equal(["event-7", "event-6", "event-5"], slice.Records.Select(record => record.CorrelationId));
        Assert.Equal(3, slice.TotalCount);
    }

    [Fact]
    public void DefaultCapacity_IsWhatTheContainerUses()
    {
        Assert.Equal(1_000, InMemorySecurityActivityStore.DefaultCapacity);
        Assert.Equal(InMemorySecurityActivityStore.DefaultCapacity, new InMemorySecurityActivityStore().Capacity);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    public void Constructor_CapacityBelowOne_Throws(int capacity)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new InMemorySecurityActivityStore(capacity));
    }

    [Theory]
    [InlineData(SecurityDecision.Allow, new[] { "allow-1", "allow-0" })]
    [InlineData(SecurityDecision.Review, new[] { "review" })]
    [InlineData(SecurityDecision.Block, new[] { "block-1", "block-0" })]
    public async Task QueryAsync_OneDecision_ReturnsOnlyThatDecision(SecurityDecision decision, string[] expected)
    {
        var store = await MixedStoreAsync();

        var slice = await store.QueryAsync(Query(decisions: [decision]), CancellationToken.None);

        Assert.Equal(expected, slice.Records.Select(record => record.CorrelationId));
        Assert.Equal(expected.Length, slice.TotalCount);
    }

    [Fact]
    public async Task QueryAsync_SeveralDecisions_ReturnsAnyOfThem()
    {
        var store = await MixedStoreAsync();

        var slice = await store.QueryAsync(Query(decisions: [SecurityDecision.Review, SecurityDecision.Block]), CancellationToken.None);

        Assert.Equal(["block-1", "review", "block-0"], slice.Records.Select(record => record.CorrelationId));
    }

    [Theory]
    [InlineData(RiskLevel.Low, 5)]
    [InlineData(RiskLevel.Medium, 3)]
    [InlineData(RiskLevel.High, 2)]
    [InlineData(RiskLevel.Critical, 1)]
    public async Task QueryAsync_MinRiskLevel_KeepsThatLevelAndAbove(RiskLevel minimum, int expected)
    {
        var store = await MixedStoreAsync();

        var slice = await store.QueryAsync(Query(minRiskLevel: minimum), CancellationToken.None);

        Assert.Equal(expected, slice.TotalCount);
        Assert.All(slice.Records, record => Assert.True(record.Risk.Level >= minimum));
    }

    [Fact]
    public async Task QueryAsync_DecisionAndMinRiskLevel_AreCombined()
    {
        var store = await MixedStoreAsync();

        var slice = await store.QueryAsync(Query(decisions: [SecurityDecision.Block], minRiskLevel: RiskLevel.Critical), CancellationToken.None);

        Assert.Equal(["block-1"], slice.Records.Select(record => record.CorrelationId));
    }

    [Fact]
    public async Task QueryAsync_SkipAndTake_PageThroughTheMatches_AndTheTotalCountsThemAll()
    {
        var store = new InMemorySecurityActivityStore();
        for (var index = 0; index < 5; index++)
        {
            await store.AppendAsync(Record(SecurityDecision.Allow, 0, $"event-{index}"), CancellationToken.None);
        }

        var first = await store.QueryAsync(Query(skip: 0, take: 2), CancellationToken.None);
        var second = await store.QueryAsync(Query(skip: 2, take: 2), CancellationToken.None);
        var last = await store.QueryAsync(Query(skip: 4, take: 2), CancellationToken.None);
        var after = await store.QueryAsync(Query(skip: 6, take: 2), CancellationToken.None);

        Assert.Equal(["event-4", "event-3"], first.Records.Select(record => record.CorrelationId));
        Assert.Equal(["event-2", "event-1"], second.Records.Select(record => record.CorrelationId));
        Assert.Equal(["event-0"], last.Records.Select(record => record.CorrelationId));
        Assert.Empty(after.Records);
        Assert.All([first, second, last, after], slice => Assert.Equal(5, slice.TotalCount));
    }

    [Fact]
    public async Task ConcurrentAppendsAndQueries_KeepTheStoreConsistentAndBounded()
    {
        var store = new InMemorySecurityActivityStore(capacity: 50);

        await Parallel.ForEachAsync(Enumerable.Range(0, 400), async (index, cancellationToken) =>
        {
            await store.AppendAsync(Record(SecurityDecision.Allow, 0, $"event-{index}"), cancellationToken);
            var slice = await store.QueryAsync(Query(take: 100), cancellationToken);
            Assert.InRange(slice.TotalCount, 1, 50);
            Assert.Equal(slice.TotalCount, slice.Records.Count);
            Assert.All(slice.Records, Assert.NotNull);
        });

        var final = await store.QueryAsync(Query(take: 100), CancellationToken.None);
        Assert.Equal(50, final.TotalCount);
        Assert.Equal(50, final.Records.Select(record => record.SecurityEventId).Distinct().Count());
    }

    [Fact]
    public async Task QueryAsync_Cancelled_Throws()
    {
        using var cancellation = new CancellationTokenSource();
        await cancellation.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new InMemorySecurityActivityStore().QueryAsync(Query(), cancellation.Token).AsTask());
    }

    [Fact]
    public async Task AppendAsync_Null_Throws()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => new InMemorySecurityActivityStore().AppendAsync(null!, CancellationToken.None).AsTask());
    }

    /// <summary>Oldest to newest: allow-0 (Low), block-0 (High), review (Medium), allow-1 (Low), block-1 (Critical).</summary>
    private static async Task<InMemorySecurityActivityStore> MixedStoreAsync()
    {
        var store = new InMemorySecurityActivityStore();
        await AppendAsync(
            store,
            Record(SecurityDecision.Allow, 0, "allow-0"),
            Record(SecurityDecision.Block, 75, "block-0"),
            Record(SecurityDecision.Review, 45, "review"),
            Record(SecurityDecision.Allow, 10, "allow-1"),
            Record(SecurityDecision.Block, 95, "block-1"));
        return store;
    }

    private static async Task AppendAsync(InMemorySecurityActivityStore store, params SecurityActivityRecord[] records)
    {
        foreach (var record in records)
        {
            await store.AppendAsync(record, CancellationToken.None);
        }
    }

    private static SecurityActivityQuery Query(SecurityDecision[]? decisions = null, RiskLevel? minRiskLevel = null, int skip = 0, int take = 25) =>
        new(decisions is null ? AnyDecision : decisions.ToHashSet(), minRiskLevel, skip, take);
}
