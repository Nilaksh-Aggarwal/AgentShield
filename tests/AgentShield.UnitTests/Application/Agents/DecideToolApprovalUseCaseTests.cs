using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Agents.Approvals;
using AgentShield.Application.Firewall;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Infrastructure.Activity;
using AgentShield.Infrastructure.Agents;
using AgentShield.UnitTests.Infrastructure.AiCapacity;
using Microsoft.Extensions.Options;

namespace AgentShield.UnitTests.Application.Agents;

/// <summary>
/// A person deciding a held call (Milestone 13): the server resolves the approval from its own state, records the decision
/// before it can take effect, and withdraws it when recording fails; listing shows metadata only.
/// </summary>
public sealed class DecideToolApprovalUseCaseTests
{
    private static readonly ToolApprovalBinding Call = new(
        new AgentId("support-agent"), "support-runtime", new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read"), new string('d', 64), null);

    private readonly ManualClock _clock = new();
    private readonly InMemoryToolApprovalStore _store;
    private readonly RecordingApprovalSink _sink = new();

    public DecideToolApprovalUseCaseTests()
    {
        _store = new InMemoryToolApprovalStore(Options.Create(new ToolApprovalOptions { LifetimeSeconds = 60 }), _clock);
    }

    [Theory]
    [InlineData(true, ToolApprovalStatus.Approved, ToolApprovalEventType.ToolApprovalApproved)]
    [InlineData(false, ToolApprovalStatus.Denied, ToolApprovalEventType.ToolApprovalDenied)]
    public async Task ExecuteAsync_APendingApproval_IsDecidedByTheAuthenticatedClient_AndRecorded(bool approve, ToolApprovalStatus status, ToolApprovalEventType recorded)
    {
        var approval = Held();

        var result = await UseCase().ExecuteAsync(approval.Id, approve, CancellationToken.None);

        Assert.True(result.IsSuccess);
        Assert.Equal((approval.Id, status), (result.Value.ApprovalId, result.Value.Status));
        var entry = Assert.Single(_sink.Entries);
        Assert.Equal((recorded, "approver-console", "corr-decide"), (entry.Type, entry.Approval.DecidedBy, entry.CorrelationId));
        Assert.Equal(status, _store.Find(approval.Id)!.Status);
    }

    [Fact]
    public async Task ExecuteAsync_UnknownDecidedOrExpired_IsAnError_AndRecordsNothing()
    {
        var decided = Held();
        var expired = Held();
        await UseCase().ExecuteAsync(decided.Id, approve: true, CancellationToken.None);
        _sink.Entries.Clear();

        var unknown = await UseCase().ExecuteAsync(Guid.NewGuid(), approve: true, CancellationToken.None);
        var again = await UseCase().ExecuteAsync(decided.Id, approve: false, CancellationToken.None);
        _clock.Advance(TimeSpan.FromSeconds(60));
        var late = await UseCase().ExecuteAsync(expired.Id, approve: true, CancellationToken.None);

        Assert.Equal(["Approval.NotFound", "Approval.AlreadyDecided", "Approval.Expired"], new[] { unknown, again, late }.Select(result => result.Errors.Single().Code));
        Assert.Empty(_sink.Entries);
        Assert.Equal(ToolApprovalStatus.Approved, _store.Find(decided.Id)!.Status);
        Assert.Equal(ToolApprovalStatus.Pending, _store.Find(expired.Id)!.Status);
        Assert.Equal(ToolApprovalStatus.Expired, _store.Find(expired.Id)!.StatusAt(_clock.GetUtcNow()));
    }

    [Fact]
    public async Task ExecuteAsync_WhileTheApprovalIsBeingRecorded_ItCannotBeUsedOrDecidedAgain_ItTakesEffectOnlyAfterwards()
    {
        var approval = Held();
        (ToolApprovalRejection? Use, ToolApprovalDecisionFailure? Decide, ToolApprovalStatus Status) seen = default;
        var observing = new RecordingApprovalSink
        {
            // An agent presenting the call, and a second person deciding, while the audit log is still being written.
            During = _ => seen = (
                _store.TryUse(approval.Id, Call, SecurityEventId.New(), _clock.GetUtcNow()).Rejection,
                _store.TryBeginDecision(approval.Id, approve: false, "second-approver", _clock.GetUtcNow()).Failure,
                _store.Find(approval.Id)!.Status),
        };

        var result = await UseCase(observing).ExecuteAsync(approval.Id, approve: true, CancellationToken.None);

        Assert.Equal((ToolApprovalRejection.NotApproved, ToolApprovalDecisionFailure.AlreadyDecided, ToolApprovalStatus.Pending), seen);
        Assert.Equal(ToolApprovalStatus.Approved, result.Value.Status);
        Assert.Equal(ToolApprovalStatus.Approved, _store.Find(approval.Id)!.Status);
        Assert.NotNull(_store.TryUse(approval.Id, Call, SecurityEventId.New(), _clock.GetUtcNow()).Approval);
    }

    [Fact]
    public async Task ExecuteAsync_RecordingTheApprovalFails_TheApprovalIsWithdrawn_AndTheRequestFails()
    {
        var approval = Held();
        var failing = new RecordingApprovalSink { Failure = new InvalidOperationException("audit down") };

        await Assert.ThrowsAsync<InvalidOperationException>(() => UseCase(failing).ExecuteAsync(approval.Id, approve: true, CancellationToken.None));

        Assert.Equal(ToolApprovalStatus.Denied, _store.Find(approval.Id)!.Status);
        Assert.Equal(ToolApprovalRejection.NotApproved, _store.TryUse(approval.Id, Call, SecurityEventId.New(), _clock.GetUtcNow()).Rejection);
    }

    [Fact]
    public async Task ExecuteAsync_TheRequestIsCancelledWhileRecording_TheApprovalIsWithdrawn()
    {
        var approval = Held();
        var cancelled = new RecordingApprovalSink { Failure = new OperationCanceledException() };

        await Assert.ThrowsAsync<OperationCanceledException>(() => UseCase(cancelled).ExecuteAsync(approval.Id, approve: true, CancellationToken.None));

        Assert.Equal(ToolApprovalStatus.Denied, _store.Find(approval.Id)!.Status);
    }

    [Fact]
    public async Task List_IsNewestFirst_WithTheStatusNow_AndMetadataOnly()
    {
        var first = Held();
        var second = Held();
        await UseCase().ExecuteAsync(second.Id, approve: false, CancellationToken.None);
        _clock.Advance(TimeSpan.FromSeconds(60));

        var items = (await new ListToolApprovalsUseCase(_store, _clock).ExecuteAsync(CancellationToken.None)).Value.Items;

        Assert.Equal([(second.Id, ToolApprovalStatus.Denied), (first.Id, ToolApprovalStatus.Expired)], items.Select(item => (item.ApprovalId, item.Status)));
        Assert.Equal(
            ["Action", "AgentId", "ApprovalId", "Capability", "CorrelationId", "DecidedAt", "ExpiresAt", "InputDecision", "Reason", "RequestedAt", "RiskLevel", "SecurityEventId", "Status", "Tool"],
            typeof(ToolApprovalResponse).GetProperties().Select(property => property.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task InputSecurityContextRecorder_RecordsTheAnalysingClientTraceAndDecision_Only()
    {
        var store = new InMemoryInputSecurityContextStore(_clock);
        var recorder = new InputSecurityContextRecorder(store, new FixedCaller("firewall-client"));
        var securityEvent = new SecurityEvent(
            SecurityEventId.New(),
            "corr-analysis",
            _clock.GetUtcNow(),
            new PolicyDecision(SecurityDecision.Review, "PolicyReview", "Medium risk."),
            new RiskAssessment(40),
            [],
            inputLength: 12,
            TimeSpan.FromMilliseconds(2));

        await recorder.PublishAsync(securityEvent, CancellationToken.None);

        var context = store.Find(securityEvent.Id)!;
        Assert.Equal(("corr-analysis", "firewall-client", SecurityDecision.Review, securityEvent.OccurredAt), (context.CorrelationId, context.Client, context.Decision, context.OccurredAt));
    }

    private ToolApproval Held()
    {
        var approval = ToolApproval.Request(
            SecurityEventId.New(),
            "corr-held",
            Call,
            new AgentActionAuthorization(AgentActionReason.HumanApprovalRequired, RiskLevel.High, new RecognisedAgentAction(Call.Agent, Call.Tool, Call.Action, Call.Capability)),
            null,
            _clock.GetUtcNow(),
            _store.Lifetime);
        _store.Add(approval);
        return approval;
    }

    private DecideToolApprovalUseCase UseCase(IToolApprovalEventSink? sink = null) =>
        new(_store, new FixedCaller("approver-console"), new FixedCorrelation("corr-decide"), [sink ?? _sink], _clock);

    private sealed class RecordingApprovalSink : IToolApprovalEventSink
    {
        public List<ToolApprovalEvent> Entries { get; } = [];

        public Exception? Failure { get; init; }

        /// <summary>Runs while the entry is being recorded, before the sink answers.</summary>
        public Action<ToolApprovalEvent>? During { get; init; }

        public ValueTask PublishAsync(ToolApprovalEvent toolApprovalEvent, CancellationToken cancellationToken)
        {
            Entries.Add(toolApprovalEvent);
            During?.Invoke(toolApprovalEvent);
            return Failure is null ? ValueTask.CompletedTask : ValueTask.FromException(Failure);
        }
    }
}
