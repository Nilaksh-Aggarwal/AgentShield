using System.Text.Json;
using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Activity;
using AgentShield.Application.Activity.ListActivity;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Infrastructure.Activity;
using static AgentShield.UnitTests.Application.Activity.ActivityTestEvents;

namespace AgentShield.UnitTests.Application.Activity;

/// <summary>
/// Agent action authorizations in the activity history: the record copies the boundary's decision, reason and risk, keeps
/// only recognised names, and is read back field by field next to the input analyses.
/// </summary>
public sealed class AgentActionActivityTests
{
    private static readonly DateTimeOffset At = new(2026, 10, 7, 9, 30, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(AgentActionReason.Permitted, RiskLevel.Low)]
    [InlineData(AgentActionReason.HumanApprovalRequired, RiskLevel.High)]
    [InlineData(AgentActionReason.CriticalActionDenied, RiskLevel.Critical)]
    [InlineData(AgentActionReason.CapabilityNotGranted, RiskLevel.Low)]
    public void FromAgentActionEvent_KeepsTheDecisionReasonRiskAndIdentifiers(AgentActionReason reason, RiskLevel risk)
    {
        var agentActionEvent = AgentEvent(new AgentActionAuthorization(reason, risk, Recognised()), "corr-agent-kept");

        var record = SecurityActivityRecord.FromAgentActionEvent(agentActionEvent);

        Assert.Equal(agentActionEvent.Id.Value, record.SecurityEventId);
        Assert.Equal(("corr-agent-kept", At), (record.CorrelationId, record.OccurredAt));
        Assert.Equal(SecurityActivityKind.AgentActionAuthorization, record.Kind);
        Assert.Equal(AgentActionReasons.DecisionFor(reason), record.Decision);
        Assert.Equal(new ActivityRisk(risk, null), record.Risk);
        Assert.Empty(record.Findings);
        Assert.Null(record.AiAnalysis);
        Assert.Equal(new ActivityAgentAction("support-agent", "email", "send", "email:send", reason), record.AgentAction);
    }

    [Fact]
    public void FromAgentActionEvent_UnrecognisedNames_AreKeptAsNull_NeverVerbatim()
    {
        // The boundary passes on only names from AgentShield's own configuration; the record keeps exactly those.
        var authorization = new AgentActionAuthorization(
            AgentActionReason.UnknownAgent,
            RiskLevel.Critical,
            new RecognisedAgentAction(null, null, null, null));

        var record = SecurityActivityRecord.FromAgentActionEvent(AgentEvent(authorization));

        Assert.Equal(new ActivityAgentAction(null, null, null, null, AgentActionReason.UnknownAgent), record.AgentAction);
        Assert.Equal(SecurityDecision.Block, record.Decision);
    }

    [Fact]
    public void FromAgentActionEvent_HoldsNoInputDecisionDurationOrOtherAuditDetail()
    {
        var record = SecurityActivityRecord.FromAgentActionEvent(AgentEvent(
            new AgentActionAuthorization(AgentActionReason.InputBlocked, RiskLevel.Low, Recognised()),
            inputDecision: SecurityDecision.Block));

        var serialised = JsonSerializer.Serialize(record);

        Assert.DoesNotContain("InputDecision", serialised, StringComparison.Ordinal);
        Assert.DoesNotContain("Duration", serialised, StringComparison.Ordinal);
        Assert.Equal(AgentActionReason.InputBlocked, record.AgentAction!.Reason);
    }

    [Fact]
    public async Task Recorder_AppendsTheRecordOfTheFinishedEvent()
    {
        var store = new InMemorySecurityActivityStore(10);
        var agentActionEvent = AgentEvent(new AgentActionAuthorization(AgentActionReason.HumanApprovalRequired, RiskLevel.High, Recognised()));

        await new AgentActionActivityRecorder(store).PublishAsync(agentActionEvent, CancellationToken.None);

        var record = Assert.Single((await store.QueryAsync(AllRecords, CancellationToken.None)).Records);
        Assert.Equal(SecurityActivityRecord.FromAgentActionEvent(agentActionEvent).AgentAction, record.AgentAction);
        Assert.Equal(agentActionEvent.Id.Value, record.SecurityEventId);
    }

    [Fact]
    public async Task Recorder_StoreFails_TheFailureIsNotSwallowed()
    {
        var recorder = new AgentActionActivityRecorder(new FailingStore());

        await Assert.ThrowsAsync<InvalidOperationException>(() => recorder.PublishAsync(
            AgentEvent(new AgentActionAuthorization(AgentActionReason.Permitted, RiskLevel.Low, Recognised())),
            CancellationToken.None).AsTask());
    }

    [Fact]
    public async Task ListActivity_MapsAgentActionsFieldByField_NextToInputAnalyses()
    {
        var store = new InMemorySecurityActivityStore(10);
        await store.AppendAsync(Record(SecurityDecision.Block, 80, "corr-input"), CancellationToken.None);
        await store.AppendAsync(SecurityActivityRecord.FromAgentActionEvent(AgentEvent(
            new AgentActionAuthorization(AgentActionReason.HumanApprovalRequired, RiskLevel.High, Recognised()), "corr-agent")), CancellationToken.None);

        var page = (await new ListActivityUseCase(store).ExecuteAsync(new ListActivityRequest(), CancellationToken.None)).Value;

        Assert.Equal(["corr-agent", "corr-input"], page.Items.Select(item => item.CorrelationId));
        var agent = page.Items[0];
        Assert.Equal(SecurityActivityKind.AgentActionAuthorization, agent.Kind);
        Assert.Equal(new ActivityRiskResponse(RiskLevel.High, null), agent.Risk);
        Assert.Equal(new ActivityAgentActionResponse("support-agent", "email", "send", "email:send", AgentActionReason.HumanApprovalRequired), agent.AgentAction);
        Assert.Null(agent.AiAnalysis);
        Assert.Empty(agent.Findings);
        var input = page.Items[1];
        Assert.Null(input.AgentAction);
        Assert.Equal(new ActivityRiskResponse(RiskLevel.High, 80), input.Risk);
    }

    [Fact]
    public async Task Store_FiltersAgentActionsByDecisionAndRiskLevel_LikeInputAnalyses()
    {
        var store = new InMemorySecurityActivityStore(10);
        await store.AppendAsync(SecurityActivityRecord.FromAgentActionEvent(AgentEvent(new AgentActionAuthorization(AgentActionReason.Permitted, RiskLevel.Low, Recognised()), "agent-low")), CancellationToken.None);
        await store.AppendAsync(SecurityActivityRecord.FromAgentActionEvent(AgentEvent(new AgentActionAuthorization(AgentActionReason.CriticalActionDenied, RiskLevel.Critical, Recognised()), "agent-critical")), CancellationToken.None);
        await store.AppendAsync(Record(SecurityDecision.Review, 45, "input-medium"), CancellationToken.None);

        var blocked = await store.QueryAsync(new SecurityActivityQuery(new HashSet<SecurityDecision> { SecurityDecision.Block }, null, 0, 10), CancellationToken.None);
        var atLeastMedium = await store.QueryAsync(new SecurityActivityQuery(new HashSet<SecurityDecision>(), RiskLevel.Medium, 0, 10), CancellationToken.None);

        Assert.Equal(["agent-critical"], blocked.Records.Select(record => record.CorrelationId));
        Assert.Equal(["input-medium", "agent-critical"], atLeastMedium.Records.Select(record => record.CorrelationId));
    }

    private static readonly SecurityActivityQuery AllRecords = new(new HashSet<SecurityDecision>(), null, 0, 10);

    private static RecognisedAgentAction Recognised() =>
        new(new AgentId("support-agent"), new ToolId("email"), new ActionName("send"), new Capability("email:send"));

    private static AgentActionEvent AgentEvent(AgentActionAuthorization authorization, string correlationId = "corr-agent", SecurityDecision? inputDecision = null) =>
        new(SecurityEventId.New(), correlationId, At, authorization, inputDecision, TimeSpan.FromMilliseconds(1));

    private sealed class FailingStore : ISecurityActivityStore
    {
        public ValueTask AppendAsync(SecurityActivityRecord record, CancellationToken cancellationToken) =>
            ValueTask.FromException(new InvalidOperationException("store down"));

        public ValueTask<SecurityActivitySlice> QueryAsync(SecurityActivityQuery query, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
