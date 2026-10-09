using System.Text.Json;
using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Activity;
using AgentShield.Application.Activity.ListActivity;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Infrastructure.Activity;

namespace AgentShield.UnitTests.Application.Activity;

/// <summary>
/// Tool gateway requests in the activity history: one record per request, from its last entry; the decision and outcome are
/// copied, never recomputed; metadata only (no arguments, no result, no argument or grant rejection reason).
/// </summary>
public sealed class ToolGatewayActivityTests
{
    private static readonly DateTimeOffset At = new(2026, 10, 7, 11, 0, 0, TimeSpan.Zero);
    private static readonly Guid ExecutionId = Guid.CreateVersion7();

    [Fact]
    public void FromToolGatewayEvent_AnExecution_IsAnAllowWithItsExecution()
    {
        var completed = Requested("corr-act-exec").Allowed(At, TimeSpan.Zero, Verdict(AgentActionReason.Permitted, RiskLevel.Low), ExecutionId).Started(At, TimeSpan.Zero).Completed(At, TimeSpan.Zero);

        var record = SecurityActivityRecord.FromToolGatewayEvent(completed);

        Assert.Equal((completed.Id.Value, "corr-act-exec", At), (record.SecurityEventId, record.CorrelationId, record.OccurredAt));
        Assert.Equal((SecurityActivityKind.ToolExecution, SecurityDecision.Allow), (record.Kind, record.Decision));
        Assert.Equal(new ActivityRisk(RiskLevel.Low, null), record.Risk);
        Assert.Empty(record.Findings);
        Assert.Null(record.AiAnalysis);
        Assert.Equal(new ActivityAgentAction("support-agent", "knowledge", "lookup", "knowledge:read", AgentActionReason.Permitted), record.AgentAction);
        Assert.Equal(new ActivityToolExecution(ToolExecutionOutcome.Executed, true, ExecutionId), record.ToolExecution);
    }

    [Theory]
    [InlineData(AgentActionReason.HumanApprovalRequired, RiskLevel.High, ToolExecutionOutcome.HeldForReview, SecurityDecision.Review)]
    [InlineData(AgentActionReason.CapabilityNotGranted, RiskLevel.Low, ToolExecutionOutcome.Denied, SecurityDecision.Block)]
    [InlineData(AgentActionReason.CriticalActionDenied, RiskLevel.Critical, ToolExecutionOutcome.Denied, SecurityDecision.Block)]
    [InlineData(AgentActionReason.Permitted, RiskLevel.Low, ToolExecutionOutcome.ToolUnavailable, SecurityDecision.Block)]
    public void FromToolGatewayEvent_ARefusal_IsCopiedWithoutAnExecution(AgentActionReason reason, RiskLevel risk, ToolExecutionOutcome outcome, SecurityDecision decision)
    {
        var rejected = Requested().Refused(At, TimeSpan.Zero, Verdict(reason, risk), outcome).Rejected(At, TimeSpan.Zero);

        var record = SecurityActivityRecord.FromToolGatewayEvent(rejected);

        Assert.Equal(decision, record.Decision);
        Assert.Equal(new ActivityRisk(risk, null), record.Risk);
        Assert.Equal(reason, record.AgentAction!.Reason);
        Assert.Equal(new ActivityToolExecution(outcome, false, null), record.ToolExecution);
    }

    [Fact]
    public void FromToolGatewayEvent_RejectedArgumentsAndGrants_KeepNoReasonCode()
    {
        var arguments = Requested().Refused(At, TimeSpan.Zero, Verdict(AgentActionReason.Permitted, RiskLevel.Low), ToolExecutionOutcome.ArgumentsRejected, ToolArgumentViolation.UnexpectedArgument).Rejected(At, TimeSpan.Zero);
        var grant = Requested().Allowed(At, TimeSpan.Zero, Verdict(AgentActionReason.Permitted, RiskLevel.Low), ExecutionId).Started(At, TimeSpan.Zero).GrantRefused(At, TimeSpan.Zero, ExecutionGrantRejection.WrongAgent);

        var argumentsRecord = JsonSerializer.Serialize(SecurityActivityRecord.FromToolGatewayEvent(arguments));
        var grantRecord = SecurityActivityRecord.FromToolGatewayEvent(grant);

        Assert.DoesNotContain(nameof(ToolArgumentViolation.UnexpectedArgument), argumentsRecord, StringComparison.Ordinal);
        Assert.DoesNotContain(nameof(ExecutionGrantRejection.WrongAgent), JsonSerializer.Serialize(grantRecord), StringComparison.Ordinal);
        Assert.Equal(new ActivityToolExecution(ToolExecutionOutcome.ExecutionAuthorizationRejected, false, ExecutionId), grantRecord.ToolExecution);
        Assert.Equal(SecurityDecision.Block, grantRecord.Decision);
    }

    [Fact]
    public void FromToolGatewayEvent_AFailedTool_IsAnInvokedAllow()
    {
        var failed = Requested().Allowed(At, TimeSpan.Zero, Verdict(AgentActionReason.Permitted, RiskLevel.Low), ExecutionId).Started(At, TimeSpan.Zero).Failed(At, TimeSpan.Zero);

        var record = SecurityActivityRecord.FromToolGatewayEvent(failed);

        Assert.Equal(SecurityDecision.Allow, record.Decision);
        Assert.Equal(new ActivityToolExecution(ToolExecutionOutcome.ExecutionFailed, true, ExecutionId), record.ToolExecution);
    }

    [Fact]
    public void FromToolGatewayEvent_OnlyALastEntry_CanBeRecorded()
    {
        var requested = Requested();
        var allowed = requested.Allowed(At, TimeSpan.Zero, Verdict(AgentActionReason.Permitted, RiskLevel.Low), ExecutionId);

        Assert.Throws<ArgumentException>(() => SecurityActivityRecord.FromToolGatewayEvent(requested));
        Assert.Throws<ArgumentException>(() => SecurityActivityRecord.FromToolGatewayEvent(allowed));
        Assert.Throws<ArgumentException>(() => SecurityActivityRecord.FromToolGatewayEvent(allowed.Started(At, TimeSpan.Zero)));
        Assert.Throws<ArgumentException>(() => SecurityActivityRecord.FromToolGatewayEvent(requested.Refused(At, TimeSpan.Zero, Verdict(AgentActionReason.CapabilityNotGranted, RiskLevel.Low), ToolExecutionOutcome.Denied)));
        Assert.Throws<ArgumentNullException>(() => SecurityActivityRecord.FromToolGatewayEvent(null!));
    }

    [Fact]
    public void FromToolGatewayEvent_UnrecognisedNames_AreKeptAsNull()
    {
        var unknownTool = new AgentActionAuthorization(AgentActionReason.UnknownTool, RiskLevel.Critical, new RecognisedAgentAction(new AgentId("support-agent"), null, null, null));
        var rejected = Requested().Refused(At, TimeSpan.Zero, unknownTool, ToolExecutionOutcome.Denied).Rejected(At, TimeSpan.Zero);

        Assert.Equal(new ActivityAgentAction("support-agent", null, null, null, AgentActionReason.UnknownTool), SecurityActivityRecord.FromToolGatewayEvent(rejected).AgentAction);
    }

    [Fact]
    public async Task Recorder_RecordsOneRecordPerRequest_FromItsLastEntryOnly()
    {
        var store = new InMemorySecurityActivityStore();
        var recorder = new ToolGatewayActivityRecorder(store);
        var requested = Requested("corr-act-recorder");
        var allowed = requested.Allowed(At, TimeSpan.Zero, Verdict(AgentActionReason.Permitted, RiskLevel.Low), ExecutionId);
        var started = allowed.Started(At, TimeSpan.Zero);

        foreach (var entry in new[] { requested, allowed, started, started.Completed(At, TimeSpan.Zero) })
        {
            await recorder.PublishAsync(entry, CancellationToken.None);
        }

        var slice = await store.QueryAsync(new SecurityActivityQuery(new HashSet<SecurityDecision>(), null, 0, 10), CancellationToken.None);
        var record = Assert.Single(slice.Records);
        Assert.Equal((SecurityActivityKind.ToolExecution, requested.Id.Value), (record.Kind, record.SecurityEventId));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await recorder.PublishAsync(null!, CancellationToken.None));
    }

    [Fact]
    public async Task Recorder_AStoreFailure_Propagates()
    {
        var recorder = new ToolGatewayActivityRecorder(new FailingStore());
        var rejected = Requested().Refused(At, TimeSpan.Zero, Verdict(AgentActionReason.CapabilityNotGranted, RiskLevel.Low), ToolExecutionOutcome.Denied).Rejected(At, TimeSpan.Zero);

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await recorder.PublishAsync(rejected, CancellationToken.None));
    }

    [Fact]
    public async Task ListActivity_MapsAToolExecution_FieldByField()
    {
        var store = new InMemorySecurityActivityStore();
        var completed = Requested("corr-act-list").Allowed(At, TimeSpan.Zero, Verdict(AgentActionReason.Permitted, RiskLevel.Low), ExecutionId).Started(At, TimeSpan.Zero).Completed(At, TimeSpan.Zero);
        await store.AppendAsync(SecurityActivityRecord.FromToolGatewayEvent(completed), CancellationToken.None);

        var page = (await new ListActivityUseCase(store).ExecuteAsync(new ListActivityRequest(), CancellationToken.None)).Value;

        var item = Assert.Single(page.Items);
        Assert.Equal(SecurityActivityKind.ToolExecution, item.Kind);
        Assert.Equal(new ActivityToolExecutionResponse(ToolExecutionOutcome.Executed, true, ExecutionId), item.ToolExecution);
        Assert.Equal(new ActivityAgentActionResponse("support-agent", "knowledge", "lookup", "knowledge:read", AgentActionReason.Permitted), item.AgentAction);
        Assert.Equal(new ActivityRiskResponse(RiskLevel.Low, null), item.Risk);
        Assert.Null(item.AiAnalysis);
    }

    private static ToolGatewayEvent Requested(string correlationId = "corr-act") =>
        ToolGatewayEvent.Requested(SecurityEventId.New(), correlationId, At, new AgentId("support-agent"), SecurityDecision.Allow);

    private static AgentActionAuthorization Verdict(AgentActionReason reason, RiskLevel risk) =>
        new(reason, risk, new RecognisedAgentAction(new AgentId("support-agent"), new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read")));

    private sealed class FailingStore : ISecurityActivityStore
    {
        public ValueTask AppendAsync(SecurityActivityRecord record, CancellationToken cancellationToken) =>
            ValueTask.FromException(new InvalidOperationException("store failure (test)"));

        public ValueTask<SecurityActivitySlice> QueryAsync(SecurityActivityQuery query, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
