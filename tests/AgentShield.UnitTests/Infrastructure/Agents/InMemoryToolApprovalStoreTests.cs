using AgentShield.Application.Abstractions.Agents;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Infrastructure.Agents;
using AgentShield.UnitTests.Infrastructure.AiCapacity;
using Microsoft.Extensions.Options;

namespace AgentShield.UnitTests.Infrastructure.Agents;

/// <summary>
/// The approval store (Milestone 13): every decision and use is one atomic check-and-transition, so an approval is decided
/// once and used once whatever the concurrency; it is bounded without ever evicting an open approval.
/// </summary>
public sealed class InMemoryToolApprovalStoreTests
{
    private static readonly ToolApprovalBinding Call = new(
        new AgentId("support-agent"), "support-runtime", new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read"), new string('a', 64), null);

    private readonly ManualClock _clock = new();
    private readonly InMemoryToolApprovalStore _store;

    public InMemoryToolApprovalStoreTests()
    {
        _store = new InMemoryToolApprovalStore(Options.Create(new ToolApprovalOptions { LifetimeSeconds = 60 }), _clock);
    }

    [Fact]
    public void Lifetime_ComesFromConfiguration()
    {
        Assert.Equal(TimeSpan.FromSeconds(60), _store.Lifetime);
        Assert.Equal(TimeSpan.FromMinutes(10), new InMemoryToolApprovalStore(Options.Create(new ToolApprovalOptions()), _clock).Lifetime);
    }

    [Fact]
    public void Decide_APendingApproval_IsDecidedOnce()
    {
        var approval = Add();

        var first = _store.Decide(approval.Id, approve: true, "approver", _clock.GetUtcNow());
        var second = _store.TryBeginDecision(approval.Id, approve: false, "approver", _clock.GetUtcNow());

        Assert.Equal(ToolApprovalStatus.Approved, first.Approval!.Status);
        Assert.Equal(ToolApprovalDecisionFailure.AlreadyDecided, second.Failure);
        Assert.Equal(ToolApprovalStatus.Approved, _store.Find(approval.Id)!.Status);
    }

    [Theory]
    [InlineData(true, ToolApprovalStatus.Approved)]
    [InlineData(false, ToolApprovalStatus.Denied)]
    public void TryBeginDecision_TheApprovalStaysPendingAndUnusable_UntilTheDecisionIsCompleted(bool approve, ToolApprovalStatus decided)
    {
        var approval = Add();

        var begun = _store.TryBeginDecision(approval.Id, approve, "approver", _clock.GetUtcNow());
        var whileRecording = _store.TryUse(approval.Id, Call, SecurityEventId.New(), _clock.GetUtcNow());
        var statusWhileRecording = _store.Find(approval.Id)!.Status;
        _store.CompleteDecision(approval.Id);

        Assert.Equal((decided, "approver"), (begun.Approval!.Status, begun.Approval.DecidedBy));
        Assert.Equal(ToolApprovalRejection.NotApproved, whileRecording.Rejection);
        Assert.Equal(ToolApprovalStatus.Pending, statusWhileRecording);
        Assert.Equal(decided, _store.Find(approval.Id)!.Status);
    }

    [Fact]
    public void TryBeginDecision_WhileADecisionIsBeingRecorded_EveryOtherDecisionIsRefused()
    {
        var approval = Add();
        _store.TryBeginDecision(approval.Id, approve: false, "approver", _clock.GetUtcNow());

        var other = _store.TryBeginDecision(approval.Id, approve: true, "second-approver", _clock.GetUtcNow());
        _store.CompleteDecision(approval.Id);

        Assert.Equal(ToolApprovalDecisionFailure.AlreadyDecided, other.Failure);
        Assert.Equal((ToolApprovalStatus.Denied, "approver"), (_store.Find(approval.Id)!.Status, _store.Find(approval.Id)!.DecidedBy));
    }

    [Fact]
    public void Revoke_WhileADecisionIsBeingRecorded_WithdrawsTheApproval_AndTheDecisionCanNeverComplete()
    {
        var approval = Add();
        _store.TryBeginDecision(approval.Id, approve: true, "approver", _clock.GetUtcNow());

        _store.Revoke(approval.Id, _clock.GetUtcNow());

        Assert.Throws<InvalidOperationException>(() => _store.CompleteDecision(approval.Id));
        Assert.Equal(ToolApprovalStatus.Denied, _store.Find(approval.Id)!.Status);
        Assert.Equal(ToolApprovalRejection.NotApproved, _store.TryUse(approval.Id, Call, SecurityEventId.New(), _clock.GetUtcNow()).Rejection);
    }

    [Fact]
    public void CompleteDecision_WithoutABegunDecision_Fails_AndChangesNothing()
    {
        var approval = Add();

        Assert.Throws<InvalidOperationException>(() => _store.CompleteDecision(approval.Id));
        Assert.Throws<InvalidOperationException>(() => _store.CompleteDecision(Guid.NewGuid()));
        Assert.Equal(ToolApprovalStatus.Pending, _store.Find(approval.Id)!.Status);
    }

    [Fact]
    public void TryBeginDecision_UnknownOrExpired_IsRefused_AndChangesNothing()
    {
        var approval = Add();
        _clock.Advance(TimeSpan.FromSeconds(60));

        Assert.Equal(ToolApprovalDecisionFailure.NotFound, _store.TryBeginDecision(Guid.NewGuid(), approve: true, "approver", _clock.GetUtcNow()).Failure);
        Assert.Equal(ToolApprovalDecisionFailure.Expired, _store.TryBeginDecision(approval.Id, approve: true, "approver", _clock.GetUtcNow()).Failure);
        Assert.Equal(ToolApprovalStatus.Pending, _store.Find(approval.Id)!.Status);
        Assert.Throws<InvalidOperationException>(() => _store.CompleteDecision(approval.Id));
    }

    [Fact]
    public void Add_WhenFull_AnApprovalWithADecisionBeingRecorded_IsNeverEvicted_AndExpiresAsUsual()
    {
        var deciding = Add();
        _store.TryBeginDecision(deciding.Id, approve: true, "approver", _clock.GetUtcNow());
        _clock.Advance(TimeSpan.FromSeconds(60));
        for (var index = 1; index < InMemoryToolApprovalStore.Capacity; index++)
        {
            Add();
        }

        Assert.Throws<InvalidOperationException>(() => Add());
        _store.CompleteDecision(deciding.Id);
        Assert.Equal(ToolApprovalStatus.Expired, _store.Find(deciding.Id)!.StatusAt(_clock.GetUtcNow()));
        Assert.Equal(ToolApprovalRejection.Expired, _store.TryUse(deciding.Id, Call, SecurityEventId.New(), _clock.GetUtcNow()).Rejection);
    }

    [Fact]
    public void TryUse_AnApprovedApproval_IsUsedOnce_ForItsCall()
    {
        var approval = Approved();
        var user = SecurityEventId.New();

        var use = _store.TryUse(approval.Id, Call, user, _clock.GetUtcNow());
        var replay = _store.TryUse(approval.Id, Call, SecurityEventId.New(), _clock.GetUtcNow());

        Assert.Equal((ToolApprovalStatus.Used, user), (use.Approval!.Status, use.Approval.UsedBy));
        Assert.Equal(ToolApprovalRejection.AlreadyUsed, replay.Rejection);
        Assert.Equal(user, _store.Find(approval.Id)!.UsedBy);
    }

    [Fact]
    public void TryUse_AnythingElse_IsRejected_AndLeavesTheApprovalAsItWas()
    {
        var pending = Add();
        var approved = Approved();
        var denied = Add();
        _store.Decide(denied.Id, approve: false, "approver", _clock.GetUtcNow());
        var otherCall = new ToolApprovalBinding(Call.Agent, Call.Client, Call.Tool, Call.Action, Call.Capability, new string('b', 64), null);

        Assert.Equal(ToolApprovalRejection.NotFound, _store.TryUse(Guid.NewGuid(), Call, SecurityEventId.New(), _clock.GetUtcNow()).Rejection);
        Assert.Equal(ToolApprovalRejection.NotApproved, _store.TryUse(pending.Id, Call, SecurityEventId.New(), _clock.GetUtcNow()).Rejection);
        Assert.Equal(ToolApprovalRejection.NotApproved, _store.TryUse(denied.Id, Call, SecurityEventId.New(), _clock.GetUtcNow()).Rejection);
        Assert.Equal(ToolApprovalRejection.WrongArguments, _store.TryUse(approved.Id, otherCall, SecurityEventId.New(), _clock.GetUtcNow()).Rejection);
        Assert.Equal(ToolApprovalStatus.Approved, _store.Find(approved.Id)!.Status);

        _clock.Advance(TimeSpan.FromSeconds(60));
        Assert.Equal(ToolApprovalRejection.Expired, _store.TryUse(approved.Id, Call, SecurityEventId.New(), _clock.GetUtcNow()).Rejection);
    }

    [Fact]
    public async Task TryUse_ConcurrentPresentations_ExactlyOneWins()
    {
        var approval = Approved();
        using var start = new ManualResetEventSlim();

        var attempts = Enumerable.Range(0, 64).Select(_ => Task.Run(() =>
        {
            start.Wait();
            return _store.TryUse(approval.Id, Call, SecurityEventId.New(), _clock.GetUtcNow());
        })).ToArray();
        start.Set();
        var results = await Task.WhenAll(attempts);

        Assert.Single(results, result => result.Approval is not null);
        Assert.Equal(63, results.Count(result => result.Rejection == ToolApprovalRejection.AlreadyUsed));
    }

    [Fact]
    public async Task TryBeginDecision_ConcurrentDecisions_ExactlyOneBegins()
    {
        var approval = Add();
        using var start = new ManualResetEventSlim();

        var attempts = Enumerable.Range(0, 64).Select(index => Task.Run(() =>
        {
            start.Wait();
            return _store.TryBeginDecision(approval.Id, approve: index % 2 == 0, "approver", _clock.GetUtcNow());
        })).ToArray();
        start.Set();
        var results = await Task.WhenAll(attempts);

        var winner = Assert.Single(results, result => result.Approval is not null);
        Assert.Equal(63, results.Count(result => result.Failure == ToolApprovalDecisionFailure.AlreadyDecided));
        _store.CompleteDecision(approval.Id);
        Assert.Equal(winner.Approval!.Status, _store.Find(approval.Id)!.Status);
    }

    [Fact]
    public void Revoke_WithdrawsAnApproval_SoItCanNeverBeUsed()
    {
        var approval = Approved();

        _store.Revoke(approval.Id, _clock.GetUtcNow());
        _store.Revoke(Guid.NewGuid(), _clock.GetUtcNow());

        Assert.Equal(ToolApprovalStatus.Denied, _store.Find(approval.Id)!.Status);
        Assert.Equal(ToolApprovalRejection.NotApproved, _store.TryUse(approval.Id, Call, SecurityEventId.New(), _clock.GetUtcNow()).Rejection);
    }

    [Fact]
    public void Recent_IsNewestFirst_AndBounded()
    {
        var first = Add();
        var second = Add();
        var third = Add();

        Assert.Equal([third.Id, second.Id, first.Id], _store.Recent(10).Select(approval => approval.Id));
        Assert.Equal([third.Id], _store.Recent(1).Select(approval => approval.Id));
        Assert.Empty(_store.Recent(0));
    }

    [Fact]
    public void Add_WhenFull_FinishedApprovalsMakeRoom_ButAnOpenApprovalIsNeverEvicted()
    {
        var used = Approved();
        _store.TryUse(used.Id, Call, SecurityEventId.New(), _clock.GetUtcNow());
        for (var index = 1; index < InMemoryToolApprovalStore.Capacity; index++)
        {
            Add();
        }

        var oneMore = Add();

        Assert.Null(_store.Find(used.Id));
        Assert.NotNull(_store.Find(oneMore.Id));
        Assert.Throws<InvalidOperationException>(() => Add());
        Assert.Equal(InMemoryToolApprovalStore.Capacity, _store.Recent(int.MaxValue).Count);
    }

    [Fact]
    public void Add_BelowCapacity_KeepsFinishedApprovals_SoAPersonStillSeesWhatWasDecided()
    {
        var denied = Add();
        _store.Decide(denied.Id, approve: false, "approver", _clock.GetUtcNow());
        var used = Approved();
        _store.TryUse(used.Id, Call, SecurityEventId.New(), _clock.GetUtcNow());

        Add();

        Assert.Equal(ToolApprovalStatus.Denied, _store.Find(denied.Id)!.Status);
        Assert.Equal(ToolApprovalRejection.AlreadyUsed, _store.TryUse(used.Id, Call, SecurityEventId.New(), _clock.GetUtcNow()).Rejection);
        Assert.Equal(3, _store.Recent(10).Count);
    }

    [Fact]
    public void Add_TheSameApprovalTwice_Fails()
    {
        var approval = Add();

        Assert.Throws<InvalidOperationException>(() => _store.Add(approval));
    }

    private ToolApproval Add()
    {
        var approval = ToolApproval.Request(
            SecurityEventId.New(),
            "corr",
            Call,
            new AgentActionAuthorization(AgentActionReason.HumanApprovalRequired, RiskLevel.High, new RecognisedAgentAction(Call.Agent, Call.Tool, Call.Action, Call.Capability)),
            null,
            _clock.GetUtcNow(),
            _store.Lifetime);
        _store.Add(approval);
        return approval;
    }

    private ToolApproval Approved()
    {
        var approval = Add();
        return _store.Decide(approval.Id, approve: true, "approver", _clock.GetUtcNow()).Approval!;
    }
}
