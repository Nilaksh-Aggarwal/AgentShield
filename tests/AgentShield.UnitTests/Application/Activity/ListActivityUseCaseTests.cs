using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Activity;
using AgentShield.Application.Activity.ListActivity;
using AgentShield.Application.Firewall.AnalyzeInput;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Domain.Threats;
using static AgentShield.UnitTests.Application.Activity.ActivityTestEvents;

namespace AgentShield.UnitTests.Application.Activity;

public class ListActivityUseCaseTests
{
    private readonly StubStore _store = new();

    [Fact]
    public async Task ExecuteAsync_NothingGiven_ReadsTheFirstPageOfEveryDecisionAndLevel()
    {
        var result = await new ListActivityUseCase(_store).ExecuteAsync(new ListActivityRequest(), CancellationToken.None);

        var query = Assert.Single(_store.Queries);
        Assert.Empty(query.Decisions);
        Assert.Null(query.MinRiskLevel);
        Assert.Equal((0, ListActivityRequest.DefaultPageSize), (query.Skip, query.Take));
        Assert.Equal((1, ListActivityRequest.DefaultPageSize), (result.Value.Page, result.Value.PageSize));
    }

    [Theory]
    [InlineData(1, 10, 0)]
    [InlineData(3, 10, 20)]
    [InlineData(ListActivityRequest.MaxPage, ListActivityRequest.MaxPageSize, (ListActivityRequest.MaxPage - 1) * ListActivityRequest.MaxPageSize)]
    public async Task ExecuteAsync_PageAndSize_BecomeSkipAndTake(int page, int pageSize, int skip)
    {
        await new ListActivityUseCase(_store).ExecuteAsync(new ListActivityRequest { Page = page, PageSize = pageSize }, CancellationToken.None);

        Assert.Equal((skip, pageSize), (_store.Queries[0].Skip, _store.Queries[0].Take));
    }

    [Fact]
    public async Task ExecuteAsync_Filters_AreParsedFromTheirExactNames()
    {
        await new ListActivityUseCase(_store).ExecuteAsync(
            new ListActivityRequest { Decision = ["Review", "Block", "Block"], MinRiskLevel = "High" },
            CancellationToken.None);

        var query = _store.Queries[0];
        Assert.Equal([SecurityDecision.Review, SecurityDecision.Block], query.Decisions.Order());
        Assert.Equal(RiskLevel.High, query.MinRiskLevel);
    }

    [Theory]
    [InlineData(0, 25, 0)]
    [InlineData(1, 25, 1)]
    [InlineData(25, 25, 1)]
    [InlineData(26, 25, 2)]
    [InlineData(1_000, 100, 10)]
    public async Task ExecuteAsync_TotalPages_CountsPagesOfMatches(int totalCount, int pageSize, int totalPages)
    {
        _store.TotalCount = totalCount;

        var result = await new ListActivityUseCase(_store).ExecuteAsync(new ListActivityRequest { PageSize = pageSize }, CancellationToken.None);

        Assert.Equal((totalCount, totalPages), (result.Value.TotalCount, result.Value.TotalPages));
    }

    [Fact]
    public async Task ExecuteAsync_MapsEachRecordToItsItem()
    {
        var ai = new AiAnalysisSummary(AiAnalysisStatus.CircuitOpen, "Gemini", "gemini-test-model", 0, TimeSpan.Zero);
        var record = SecurityActivityRecord.FromSecurityEvent(Event(SecurityDecision.Review, 45, "corr-map-1", Start, ai, findings:
        [
            Finding("InconclusiveAnalysis.AiAnalysisIncomplete", ThreatCategory.InconclusiveAnalysis, ThreatSeverity.Medium),
        ]));
        _store.Records = [record];
        _store.TotalCount = 1;

        var result = await new ListActivityUseCase(_store).ExecuteAsync(new ListActivityRequest(), CancellationToken.None);

        var item = Assert.Single(result.Value.Items);
        Assert.Equal(record.SecurityEventId, item.SecurityEventId);
        Assert.Equal(("corr-map-1", Start, SecurityActivityKind.InputAnalysis), (item.CorrelationId, item.OccurredAt, item.Kind));
        Assert.Equal(SecurityDecision.Review, item.Decision);
        Assert.Equal(new ActivityRiskResponse(RiskLevel.Medium, 45), item.Risk);
        Assert.Equal([new ActivityFindingResponse("InconclusiveAnalysis.AiAnalysisIncomplete", ThreatCategory.InconclusiveAnalysis, ThreatSeverity.Medium)], item.Findings);
        Assert.Equal(ActivityAiStatus.Incomplete, item.AiAnalysis);
        Assert.Null(item.AgentAction);
    }

    [Theory]
    [InlineData("block", null)]
    [InlineData(null, "high")]
    public async Task ExecuteAsync_UnvalidatedName_Throws(string? decision, string? minRiskLevel)
    {
        var request = new ListActivityRequest { Decision = decision is null ? null : [decision], MinRiskLevel = minRiskLevel };

        await Assert.ThrowsAsync<ArgumentException>(() => new ListActivityUseCase(_store).ExecuteAsync(request, CancellationToken.None));
        Assert.Empty(_store.Queries);
    }

    private sealed class StubStore : ISecurityActivityStore
    {
        public List<SecurityActivityQuery> Queries { get; } = [];

        public IReadOnlyList<SecurityActivityRecord> Records { get; set; } = [];

        public int TotalCount { get; set; }

        public ValueTask AppendAsync(SecurityActivityRecord record, CancellationToken cancellationToken) => throw new NotSupportedException();

        public ValueTask<SecurityActivitySlice> QueryAsync(SecurityActivityQuery query, CancellationToken cancellationToken)
        {
            Queries.Add(query);
            return ValueTask.FromResult(new SecurityActivitySlice(Records, TotalCount));
        }
    }
}
