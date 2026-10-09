using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Activity;
using AgentShield.Application.Activity.SummariseActivity;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Infrastructure.Activity;
using static AgentShield.UnitTests.Application.Activity.ActivityTestEvents;

namespace AgentShield.UnitTests.Application.Activity;

/// <summary>
/// The activity summary counts what the history holds, from one snapshot: decisions and kinds copied from the records, a
/// tool counted as executed only when its outcome says so, counts only.
/// </summary>
public sealed class ActivitySummaryUseCaseTests
{
    private static readonly AgentActionAuthorization Permitted = Verdict(AgentActionReason.Permitted, RiskLevel.Low);

    [Fact]
    public async Task ExecuteAsync_AnEmptyHistory_IsAllZeros_WithoutATimeRange()
    {
        var summary = await Summarise(new InMemorySecurityActivityStore());

        Assert.Equal(new ActivitySummaryResponse(0, null, null, new ActivityDecisionCounts(0, 0, 0), new ActivityKindCounts(0, 0, 0), 0), summary);
    }

    [Fact]
    public async Task ExecuteAsync_CountsEveryKindAndDecision_AsTheRecordsHoldThem()
    {
        var store = new InMemorySecurityActivityStore();
        await Append(store, SecurityActivityRecord.FromSecurityEvent(Event(SecurityDecision.Allow, 0, occurredAt: Start)));
        await Append(store, SecurityActivityRecord.FromSecurityEvent(Event(SecurityDecision.Block, 90, occurredAt: Start.AddMinutes(1))));
        await Append(store, SecurityActivityRecord.FromSecurityEvent(Event(SecurityDecision.Allow, 5, occurredAt: Start.AddMinutes(1.5))));
        await Append(store, SecurityActivityRecord.FromSecurityEvent(Event(SecurityDecision.Review, 40, occurredAt: Start.AddMinutes(2))));
        await Append(store, SecurityActivityRecord.FromAgentActionEvent(new AgentActionEvent(SecurityEventId.New(), "corr", Start.AddMinutes(3), Verdict(AgentActionReason.HumanApprovalRequired, RiskLevel.High), null, TimeSpan.Zero)));
        await Append(store, Tool(Executed, Start.AddMinutes(4)));
        await Append(store, Tool(Refused(AgentActionReason.CapabilityNotGranted, ToolExecutionOutcome.Denied), Start.AddMinutes(5)));

        var summary = await Summarise(store);

        // Every count differs from the count of the other records, so an inverted comparison cannot pass (mutation run).
        Assert.Equal(7, summary.TotalCount);
        Assert.Equal(new ActivityDecisionCounts(Allow: 3, Review: 2, Block: 2), summary.Decisions);
        Assert.Equal(new ActivityKindCounts(InputAnalysis: 4, AgentActionAuthorization: 1, ToolExecution: 2), summary.Kinds);
        Assert.Equal(1, summary.ToolsExecuted);
        Assert.Equal((Start, Start.AddMinutes(5)), (summary.OldestOccurredAt!.Value, summary.NewestOccurredAt!.Value));
    }

    [Fact]
    public async Task ExecuteAsync_OnlyACompletedTool_CountsAsExecuted()
    {
        // A failed tool was invoked but returned nothing; a refused grant, a held or blocked call never ran.
        var store = new InMemorySecurityActivityStore();
        await Append(store, Tool(Executed, Start));
        await Append(store, Tool(Failed, Start));
        await Append(store, Tool(GrantRefused, Start));
        await Append(store, Tool(Refused(AgentActionReason.HumanApprovalRequired, ToolExecutionOutcome.HeldForReview), Start));
        await Append(store, Tool(Refused(AgentActionReason.Permitted, ToolExecutionOutcome.ArgumentsRejected, ToolArgumentViolation.UnexpectedArgument), Start));
        await Append(store, Tool(Refused(AgentActionReason.Permitted, ToolExecutionOutcome.ToolUnavailable), Start));

        var summary = await Summarise(store);

        Assert.Equal(1, summary.ToolsExecuted);
        Assert.Equal(6, summary.Kinds.ToolExecution);
        Assert.Equal(new ActivityDecisionCounts(Allow: 2, Review: 1, Block: 3), summary.Decisions);
    }

    [Fact]
    public async Task ExecuteAsync_CountsWhatTheBoundedHistoryHolds_NotEverythingEverRecorded()
    {
        var store = new InMemorySecurityActivityStore(capacity: 3);
        for (var index = 0; index < 5; index++)
        {
            await Append(store, SecurityActivityRecord.FromSecurityEvent(Event(SecurityDecision.Block, 90, occurredAt: Start.AddMinutes(index))));
        }

        var summary = await Summarise(store);

        Assert.Equal(3, summary.TotalCount);
        Assert.Equal((Start.AddMinutes(2), Start.AddMinutes(4)), (summary.OldestOccurredAt!.Value, summary.NewestOccurredAt!.Value));
    }

    [Fact]
    public async Task ExecuteAsync_ReadsTheWholeHistoryOnce_WithoutAFilter()
    {
        var store = new RecordingStore();

        await Summarise(store);

        var query = Assert.Single(store.Queries);
        Assert.Empty(query.Decisions);
        Assert.Null(query.MinRiskLevel);
        Assert.Equal((0, int.MaxValue), (query.Skip, query.Take));
    }

    [Fact]
    public void Response_HoldsCountsAndTimesOnly()
    {
        string[] Names<T>() => [.. typeof(T).GetProperties().Select(property => property.Name).Order(StringComparer.Ordinal)];

        Assert.Equal(["Decisions", "Kinds", "NewestOccurredAt", "OldestOccurredAt", "ToolsExecuted", "TotalCount"], Names<ActivitySummaryResponse>());
        Assert.Equal(["Allow", "Block", "Review"], Names<ActivityDecisionCounts>());
        Assert.Equal(["AgentActionAuthorization", "InputAnalysis", "ToolExecution"], Names<ActivityKindCounts>());
    }

    private static async Task<ActivitySummaryResponse> Summarise(ISecurityActivityStore store) =>
        (await new ActivitySummaryUseCase(store).ExecuteAsync(CancellationToken.None)).Value;

    private static ValueTask Append(InMemorySecurityActivityStore store, SecurityActivityRecord record) => store.AppendAsync(record, CancellationToken.None);

    private static SecurityActivityRecord Tool(Func<ToolGatewayEvent, ToolGatewayEvent> finish, DateTimeOffset at) =>
        SecurityActivityRecord.FromToolGatewayEvent(finish(ToolGatewayEvent.Requested(SecurityEventId.New(), "corr-tool", at, new AgentId("research-agent"), null)));

    private static ToolGatewayEvent Executed(ToolGatewayEvent requested) => Started(requested).Completed(requested.OccurredAt, TimeSpan.Zero);

    private static ToolGatewayEvent Failed(ToolGatewayEvent requested) => Started(requested).Failed(requested.OccurredAt, TimeSpan.Zero);

    private static ToolGatewayEvent GrantRefused(ToolGatewayEvent requested) => Started(requested).GrantRefused(requested.OccurredAt, TimeSpan.Zero, ExecutionGrantRejection.AlreadyUsed);

    private static ToolGatewayEvent Started(ToolGatewayEvent requested) =>
        requested.Allowed(requested.OccurredAt, TimeSpan.Zero, Permitted, Guid.CreateVersion7()).Started(requested.OccurredAt, TimeSpan.Zero);

    private static Func<ToolGatewayEvent, ToolGatewayEvent> Refused(AgentActionReason reason, ToolExecutionOutcome outcome, ToolArgumentViolation? violation = null) =>
        requested => requested.Refused(requested.OccurredAt, TimeSpan.Zero, Verdict(reason, RiskLevel.Low), outcome, violation).Rejected(requested.OccurredAt, TimeSpan.Zero);

    private static AgentActionAuthorization Verdict(AgentActionReason reason, RiskLevel risk) =>
        new(reason, risk, new RecognisedAgentAction(new AgentId("research-agent"), new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read")));

    private sealed class RecordingStore : ISecurityActivityStore
    {
        public List<SecurityActivityQuery> Queries { get; } = [];

        public ValueTask AppendAsync(SecurityActivityRecord record, CancellationToken cancellationToken) => ValueTask.CompletedTask;

        public ValueTask<SecurityActivitySlice> QueryAsync(SecurityActivityQuery query, CancellationToken cancellationToken)
        {
            Queries.Add(query);
            return ValueTask.FromResult(new SecurityActivitySlice([], 0));
        }
    }
}
