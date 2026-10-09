using System.Text.Json;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Application.Agents.ExecuteTool;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Infrastructure.Activity;
using AgentShield.Infrastructure.Agents;
using AgentShield.UnitTests.Infrastructure.AiCapacity;
using AgentShield.UnitTests.Infrastructure.Agents;
using Microsoft.Extensions.Options;

namespace AgentShield.UnitTests.Application.Agents;

/// <summary>
/// Milestone 13 at the tool gateway: a held call runs only with a person's approval of exactly that call, used once; the
/// input decision is the server's record of the referenced analysis, never weakened by the caller; and every Block, held or
/// unverifiable call runs nothing.
/// </summary>
public sealed class ToolGatewayApprovalTests
{
    private const string Runtime = "support-runtime";
    private const string OtherRuntime = "other-runtime";
    private const string Correlation = "corr-approval";
    private const string Arguments = """{"query":"dependency injection"}""";

    private static readonly AgentProfile Support = new(new AgentId("support-agent"), [new Capability("knowledge:read")], [Runtime], gatewayClient: Runtime);
    private static readonly AgentProfile Other = new(new AgentId("other-agent"), [new Capability("knowledge:read")], [OtherRuntime], gatewayClient: OtherRuntime);

    private readonly ScriptedAuthorizer _authorizer = new(ScriptedAuthorizer.For(AgentActionReason.HumanApprovalRequired, RiskLevel.High));
    private readonly ScriptedArgumentPolicy _policy = new("knowledge", "lookup");
    private readonly ScriptedExecutionAuthority _authority = new();
    private readonly RecordingGatewaySink _sink = new();
    private readonly ManualClock _clock = new();
    private readonly InMemoryInputSecurityContextStore _inputs;
    private readonly InMemoryToolApprovalStore _approvals;

    public ToolGatewayApprovalTests()
    {
        _inputs = new InMemoryInputSecurityContextStore(_clock);
        _approvals = new InMemoryToolApprovalStore(Options.Create(new ToolApprovalOptions { LifetimeSeconds = 300 }), _clock);
    }

    // ── Human approval ─────────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Review_WithoutAnApproval_IsHeld_RunsNothing_AndCreatesAPendingApprovalOfExactlyThisCall()
    {
        var response = (await Gateway().ExecuteAsync(Request(), CancellationToken.None)).Value;

        Assert.Equal((SecurityDecision.Review, false, ToolExecutionOutcome.HeldForReview), (response.Decision, response.Executed, response.Outcome));
        var approval = Assert.Single(_approvals.Recent(10));
        Assert.Equal(approval.Id, response.ApprovalId);
        Assert.Equal(ToolApprovalStatus.Pending, approval.Status);
        Assert.Equal(response.SecurityEventId, approval.RequestEventId.Value);
        Assert.Equal((new AgentId("support-agent"), Runtime, new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read")),
            (approval.Binding.Agent, approval.Binding.Client, approval.Binding.Tool, approval.Binding.Action, approval.Binding.Capability));
        Assert.Equal((RiskLevel.High, AgentActionReason.HumanApprovalRequired), (approval.Risk, approval.Reason));
        Assert.Equal(_clock.GetUtcNow() + _approvals.Lifetime, approval.ExpiresAt);

        Assert.Equal([ToolGatewayEventType.ToolAuthorizationRequested, ToolGatewayEventType.ToolAuthorizationReviewed, ToolGatewayEventType.ToolExecutionRejected], _sink.Types);
        Assert.All(_sink.Entries.Skip(1), entry => Assert.Equal(approval.Id, entry.ApprovalId));
        Assert.Empty(_authority.Issued);
        Assert.Empty(_authority.Executions);
        Assert.Equal(0, _policy.Checks);
    }

    [Fact]
    public async Task Review_ForAnActionNoToolHereRuns_IsHeld_WithoutAnApproval()
    {
        var response = (await Gateway(policies: []).ExecuteAsync(Request(), CancellationToken.None)).Value;

        Assert.Equal(ToolExecutionOutcome.HeldForReview, response.Outcome);
        Assert.Null(response.ApprovalId);
        Assert.Empty(_approvals.Recent(10));
    }

    [Fact]
    public async Task ApprovedReview_PresentedWithTheSameCall_RunsOnce_AndTheApprovalIsUsedByThatRequest()
    {
        var approvalId = await HoldAndDecideAsync(approve: true);

        var response = (await Gateway().ExecuteAsync(Request(approvalId: approvalId), CancellationToken.None)).Value;

        Assert.Equal((SecurityDecision.Allow, true, ToolExecutionOutcome.Executed), (response.Decision, response.Executed, response.Outcome));
        Assert.Equal((AgentActionReason.HumanApprovalRequired, approvalId), (response.AuthorizationReason, response.ApprovalId));
        var used = _approvals.Find(approvalId)!;
        Assert.Equal((ToolApprovalStatus.Used, response.SecurityEventId), (used.Status, used.UsedBy!.Value.Value));
        Assert.Equal(approvalId, Assert.Single(_authority.Issued).ApprovalId);
        Assert.Single(_authority.Executions);

        var entries = _sink.Entries.Where(entry => entry.Id.Value == response.SecurityEventId).ToList();
        Assert.Equal(
            [ToolGatewayEventType.ToolAuthorizationRequested, ToolGatewayEventType.ToolAuthorizationAllowed, ToolGatewayEventType.ToolExecutionStarted, ToolGatewayEventType.ToolExecutionCompleted],
            entries.Select(entry => entry.Type));
        Assert.Equal(SecurityDecision.Review, entries[1].Authorization!.Decision);
        Assert.Equal(approvalId, entries[1].ApprovalId);
    }

    [Fact]
    public async Task ApprovedReview_PresentedTwice_RunsOnce()
    {
        var approvalId = await HoldAndDecideAsync(approve: true);

        await Gateway().ExecuteAsync(Request(approvalId: approvalId), CancellationToken.None);
        var replay = (await Gateway().ExecuteAsync(Request(approvalId: approvalId), CancellationToken.None)).Value;

        Assert.Equal((SecurityDecision.Block, false, ToolExecutionOutcome.ApprovalRejected), (replay.Decision, replay.Executed, replay.Outcome));
        Assert.Equal(ToolApprovalRejection.AlreadyUsed, _sink.Entries.Last(entry => entry.Id.Value == replay.SecurityEventId).ApprovalRejection);
        Assert.Single(_authority.Executions);
    }

    [Theory]
    [InlineData("denied", ToolApprovalRejection.NotApproved)]
    [InlineData("pending", ToolApprovalRejection.NotApproved)]
    [InlineData("expired", ToolApprovalRejection.Expired)]
    [InlineData("unknown", ToolApprovalRejection.NotFound)]
    public async Task AHeldCall_WithoutAValidApproval_RunsNothing(string state, ToolApprovalRejection expected)
    {
        var approvalId = state switch
        {
            "denied" => await HoldAndDecideAsync(approve: false),
            "pending" => await HoldAsync(),
            "expired" => await HoldAndDecideAsync(approve: true, thenAdvance: TimeSpan.FromSeconds(300)),
            _ => Guid.NewGuid(),
        };

        var response = (await Gateway().ExecuteAsync(Request(approvalId: approvalId), CancellationToken.None)).Value;

        Assert.Equal((SecurityDecision.Block, false, ToolExecutionOutcome.ApprovalRejected), (response.Decision, response.Executed, response.Outcome));
        Assert.Equal(expected, _sink.Entries.Last().ApprovalRejection);
        Assert.Empty(_authority.Issued);
        Assert.Empty(_authority.Executions);
        Assert.Equal(0, _policy.Checks);
    }

    [Fact]
    public async Task AnApproval_ForOneCall_DoesNotAuthoriseOtherArguments_OrAnotherAgent()
    {
        var approvalId = await HoldAndDecideAsync(approve: true);

        var otherArguments = (await Gateway().ExecuteAsync(Request("""{"query":"least privilege"}""", approvalId: approvalId), CancellationToken.None)).Value;
        var otherAgent = (await Gateway(caller: OtherRuntime).ExecuteAsync(Request(approvalId: approvalId), CancellationToken.None)).Value;
        var reordered = (await Gateway().ExecuteAsync(Request("""{ "query":"dependency injection"}""", approvalId: approvalId), CancellationToken.None)).Value;

        Assert.All([otherArguments, otherAgent, reordered], response => Assert.Equal(ToolExecutionOutcome.ApprovalRejected, response.Outcome));
        Assert.Equal(
            [ToolApprovalRejection.WrongArguments, ToolApprovalRejection.WrongAgent, ToolApprovalRejection.WrongArguments],
            new[] { otherArguments, otherAgent, reordered }.Select(response => _sink.Entries.Last(entry => entry.Id.Value == response.SecurityEventId).ApprovalRejection));
        Assert.Empty(_authority.Executions);
        Assert.Equal(ToolApprovalStatus.Approved, _approvals.Find(approvalId)!.Status);
    }

    [Fact]
    public async Task ABlock_IsNeverLiftedByAnApproval_AndLeavesItUnused()
    {
        var approvalId = await HoldAndDecideAsync(approve: true);
        _authorizer.Verdict = ScriptedAuthorizer.For(AgentActionReason.CriticalActionDenied, RiskLevel.Critical);

        var response = (await Gateway().ExecuteAsync(Request(approvalId: approvalId), CancellationToken.None)).Value;

        Assert.Equal((SecurityDecision.Block, ToolExecutionOutcome.Denied), (response.Decision, response.Outcome));
        Assert.Equal(ToolApprovalStatus.Approved, _approvals.Find(approvalId)!.Status);
        Assert.Empty(_authority.Executions);
    }

    [Fact]
    public async Task AnAllow_RunsWithoutUsingAPresentedApproval()
    {
        var approvalId = await HoldAndDecideAsync(approve: true);
        _authorizer.Verdict = ScriptedAuthorizer.For(AgentActionReason.Permitted, RiskLevel.Low);

        var response = (await Gateway().ExecuteAsync(Request(approvalId: approvalId), CancellationToken.None)).Value;

        Assert.Equal(ToolExecutionOutcome.Executed, response.Outcome);
        Assert.Null(response.ApprovalId);
        Assert.Null(Assert.Single(_authority.Issued).ApprovalId);
        Assert.Equal(ToolApprovalStatus.Approved, _approvals.Find(approvalId)!.Status);
    }

    [Fact]
    public async Task ApprovedCall_ThatBreaksTheArgumentPolicy_IsBlocked_AndTheApprovalIsSpent()
    {
        var approvalId = await HoldAndDecideAsync(approve: true);
        var rejecting = new ScriptedArgumentPolicy("knowledge", "lookup", ToolArgumentViolation.TooLong);

        var response = (await Gateway(policies: [rejecting]).ExecuteAsync(Request(approvalId: approvalId), CancellationToken.None)).Value;

        Assert.Equal(ToolExecutionOutcome.ArgumentsRejected, response.Outcome);
        Assert.Equal(approvalId, response.ApprovalId);
        Assert.Equal(ToolApprovalStatus.Used, _approvals.Find(approvalId)!.Status);
        Assert.Empty(_authority.Executions);
    }

    [Fact]
    public async Task RecordingTheHeldRequestFails_TheNewApprovalIsWithdrawn_SoItCanNeverRun()
    {
        var failing = new RecordingGatewaySink(ToolGatewayEventType.ToolExecutionRejected);

        await Assert.ThrowsAsync<InvalidOperationException>(() => Gateway(sinks: [failing]).ExecuteAsync(Request(), CancellationToken.None));

        var approval = Assert.Single(_approvals.Recent(10));
        Assert.Equal(ToolApprovalStatus.Denied, approval.Status);
    }

    [Fact]
    public async Task RecordingTheReviewFails_NoApprovalIsCreated()
    {
        var failing = new RecordingGatewaySink(ToolGatewayEventType.ToolAuthorizationReviewed);

        await Assert.ThrowsAsync<InvalidOperationException>(() => Gateway(sinks: [failing]).ExecuteAsync(Request(), CancellationToken.None));

        Assert.Empty(_approvals.Recent(10));
    }

    // ── Input security event binding ───────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(SecurityDecision.Allow, null, SecurityDecision.Allow)]
    [InlineData(SecurityDecision.Review, null, SecurityDecision.Review)]
    [InlineData(SecurityDecision.Block, null, SecurityDecision.Block)]
    [InlineData(SecurityDecision.Block, SecurityDecision.Allow, SecurityDecision.Block)]
    [InlineData(SecurityDecision.Review, SecurityDecision.Allow, SecurityDecision.Review)]
    [InlineData(SecurityDecision.Allow, SecurityDecision.Block, SecurityDecision.Block)]
    [InlineData(SecurityDecision.Allow, SecurityDecision.Review, SecurityDecision.Review)]
    public async Task AReferencedInputEvent_DecidesTheInput_AndTheCallerCanOnlyTighten(SecurityDecision recorded, SecurityDecision? claimed, SecurityDecision applied)
    {
        _authorizer.Verdict = ScriptedAuthorizer.For(AgentActionReason.Permitted, RiskLevel.Low);
        var eventId = await AnalysedAsync(recorded);

        await Gateway().ExecuteAsync(Request(inputDecision: claimed, inputEventId: eventId), CancellationToken.None);

        Assert.Equal(applied, Assert.Single(_authorizer.Received).InputDecision);
        Assert.Equal((applied, SecurityEventId.From(eventId)), (_sink.Entries[0].InputDecision, _sink.Entries[0].InputEventId!.Value));
    }

    [Theory]
    [InlineData("unknown", InputContextRejection.NotFound)]
    [InlineData("other client", InputContextRejection.OtherClient)]
    [InlineData("other trace", InputContextRejection.OtherTrace)]
    [InlineData("expired", InputContextRejection.Expired)]
    public async Task AnInputEventThatCannotBeVerified_BlocksTheCall_WhateverTheBoundarySays(string problem, InputContextRejection expected)
    {
        _authorizer.Verdict = ScriptedAuthorizer.For(AgentActionReason.Permitted, RiskLevel.Low);
        var eventId = problem switch
        {
            "unknown" => Guid.NewGuid(),
            "other client" => await AnalysedAsync(SecurityDecision.Allow, client: OtherRuntime),
            "other trace" => await AnalysedAsync(SecurityDecision.Allow, correlationId: "corr-another-trace"),
            _ => await AnalysedAsync(SecurityDecision.Allow),
        };
        if (problem == "expired")
        {
            _clock.Advance(InputSecurityContext.Lifetime);
        }

        var response = (await Gateway().ExecuteAsync(Request(inputDecision: SecurityDecision.Allow, inputEventId: eventId), CancellationToken.None)).Value;

        Assert.Equal((SecurityDecision.Block, false, ToolExecutionOutcome.InputContextRejected), (response.Decision, response.Executed, response.Outcome));
        Assert.Equal(expected, _sink.Entries.Last().InputContextRejection);
        Assert.Single(_authorizer.Received);
        Assert.Empty(_authority.Issued);
        Assert.Empty(_authority.Executions);
        Assert.Empty(_approvals.Recent(10));
    }

    [Fact]
    public async Task AnInputEventHeldForReview_HoldsTheCall_AndItsApprovalCarriesThatEvent()
    {
        _authorizer.Verdict = ScriptedAuthorizer.For(AgentActionReason.InputHeldForReview, RiskLevel.Low);
        var eventId = await AnalysedAsync(SecurityDecision.Review);

        var held = (await Gateway().ExecuteAsync(Request(inputEventId: eventId), CancellationToken.None)).Value;
        var approval = _approvals.Find(held.ApprovalId!.Value)!;

        Assert.Equal(ToolExecutionOutcome.HeldForReview, held.Outcome);
        Assert.Equal((SecurityDecision.Review, SecurityEventId.From(eventId)), (approval.InputDecision, approval.Binding.InputEventId!.Value));

        // Presenting the approval with the same call in a later trace, without repeating the event: the approved input decision
        // still applies, so the call is still a Review and runs only through the approval.
        _approvals.Decide(approval.Id, approve: true, "approver", _clock.GetUtcNow());
        var ran = (await Gateway(correlationId: "corr-later").ExecuteAsync(Request(approvalId: approval.Id), CancellationToken.None)).Value;

        Assert.Equal(ToolExecutionOutcome.Executed, ran.Outcome);
        Assert.Equal(SecurityDecision.Review, _authorizer.Received.Last().InputDecision);
    }

    [Fact]
    public async Task AnApproval_CannotWeakenAReferencedBlockedInput()
    {
        var approvalId = await HoldAndDecideAsync(approve: true);
        var blocked = await AnalysedAsync(SecurityDecision.Block);

        await Gateway().ExecuteAsync(Request(approvalId: approvalId, inputEventId: blocked), CancellationToken.None);

        Assert.Equal(SecurityDecision.Block, _authorizer.Received.Last().InputDecision);
    }

    // ── F7 and recording ───────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task TheToolGetsExactlyTheArgumentsValidatedInTheSameRequest_UnderThatRequestsOneGrant()
    {
        // F7: the grant's scope names the call but not its arguments. It is safe because the gateway builds the presented call
        // from the arguments the policy validated in the same request, presents the grant issued in that request, once, and a
        // grant never leaves the process: there is no point where other arguments can meet that grant.
        _authorizer.Verdict = ScriptedAuthorizer.For(AgentActionReason.Permitted, RiskLevel.Low);
        var policy = new CapturingPolicy();

        var response = (await Gateway(policies: [policy]).ExecuteAsync(Request(), CancellationToken.None)).Value;

        var (grant, call) = Assert.Single(_authority.Executions);
        Assert.Same(policy.Accepted, call.Arguments);
        Assert.Same(Assert.Single(_authority.Grants), grant);
        Assert.Equal(response.SecurityEventId, grant.Scope.SecurityEventId.Value);
        Assert.Equal(grant.Scope, call.Scope);
    }

    [Fact]
    public async Task ARequestCancelledAfterTheToolRan_StillRecordsTheCompletion()
    {
        _authorizer.Verdict = ScriptedAuthorizer.For(AgentActionReason.Permitted, RiskLevel.Low);
        using var request = new CancellationTokenSource();
        var sink = new TokenHonouringSink();
        var authority = new CancelThenRunAuthority(request);

        var result = await Gateway(authority: authority, sinks: [sink]).ExecuteAsync(Request(), request.Token);

        Assert.Equal(ToolExecutionOutcome.Executed, result.Value.Outcome);
        Assert.Equal(ToolGatewayEventType.ToolExecutionCompleted, sink.Recorded.Last());
    }

    [Fact]
    public async Task ACancelledSink_DoesNotSkipTheOtherSinks()
    {
        _authorizer.Verdict = ScriptedAuthorizer.For(AgentActionReason.Permitted, RiskLevel.Low);
        var cancelled = new RecordingGatewaySink(ToolGatewayEventType.ToolAuthorizationRequested, new OperationCanceledException());
        var after = new RecordingGatewaySink();

        await Assert.ThrowsAsync<OperationCanceledException>(() => Gateway(sinks: [cancelled, after]).ExecuteAsync(Request(), CancellationToken.None));

        Assert.Equal([ToolGatewayEventType.ToolAuthorizationRequested], after.Types);
        Assert.Empty(_authority.Executions);
    }

    // ── Helpers ────────────────────────────────────────────────────────────────────────────────────────────────────────

    private async Task<Guid> HoldAsync() =>
        (await Gateway().ExecuteAsync(Request(), CancellationToken.None)).Value.ApprovalId ?? throw new InvalidOperationException("No approval was created.");

    private async Task<Guid> HoldAndDecideAsync(bool approve, TimeSpan? thenAdvance = null)
    {
        var approvalId = await HoldAsync();
        Assert.NotNull(_approvals.Decide(approvalId, approve, "approver-console", _clock.GetUtcNow()).Approval);
        if (thenAdvance is { } wait)
        {
            _clock.Advance(wait);
        }

        return approvalId;
    }

    private async Task<Guid> AnalysedAsync(SecurityDecision decision, string client = Runtime, string correlationId = Correlation)
    {
        var context = new InputSecurityContext(SecurityEventId.New(), correlationId, client, decision, _clock.GetUtcNow());
        await _inputs.RecordAsync(context, CancellationToken.None);
        return context.SecurityEventId.Value;
    }

    private ToolGateway Gateway(
        string caller = Runtime,
        string correlationId = Correlation,
        IToolArgumentPolicy[]? policies = null,
        IToolExecutionAuthority? authority = null,
        IToolGatewayEventSink[]? sinks = null) =>
        new(
            new FixedCaller(caller),
            new FixedCorrelation(correlationId),
            new GatewayDirectory([Support, Other]),
            _authorizer,
            policies ?? [_policy],
            authority ?? _authority,
            _inputs,
            _approvals,
            sinks ?? [_sink],
            _clock);

    private static ExecuteToolRequest Request(string arguments = Arguments, SecurityDecision? inputDecision = null, Guid? approvalId = null, Guid? inputEventId = null)
    {
        using var document = JsonDocument.Parse(arguments);
        return new ExecuteToolRequest("knowledge", "lookup", "knowledge:read", document.RootElement.Clone(), inputDecision, inputEventId, approvalId);
    }

    private sealed class CapturingPolicy : IToolArgumentPolicy
    {
        public ToolId Tool { get; } = new("knowledge");

        public ActionName Action { get; } = new("lookup");

        public ToolArguments? Accepted { get; private set; }

        public ToolArgumentCheck Check(JsonElement arguments)
        {
            var accepted = new KnowledgeLookupArguments("dependency injection");
            Accepted = accepted;
            return ToolArgumentCheck.Accept(accepted);
        }
    }

    /// <summary>The request is cancelled while the tool runs, but the tool completes.</summary>
    private sealed class CancelThenRunAuthority(CancellationTokenSource request) : IToolExecutionAuthority
    {
        private readonly ScriptedExecutionAuthority _inner = new();

        public ExecutionGrant? Issue(AgentActionRequest proposal, SecurityEventId securityEventId, string correlationId, Guid? approvalId = null) =>
            _inner.Issue(proposal, securityEventId, correlationId, approvalId);

        public async ValueTask<ToolExecutionAttempt> ExecuteAsync(ExecutionGrant grant, ToolCall call, CancellationToken cancellationToken)
        {
            await request.CancelAsync();
            return ToolExecutionAttempt.Ran(new ToolOutput(found: true, "ran"));
        }
    }

    /// <summary>Records an entry only when its token is not cancelled, like a sink that honours cancellation.</summary>
    private sealed class TokenHonouringSink : IToolGatewayEventSink
    {
        public List<ToolGatewayEventType> Recorded { get; } = [];

        public ValueTask PublishAsync(ToolGatewayEvent toolGatewayEvent, CancellationToken cancellationToken)
        {
            if (cancellationToken.IsCancellationRequested)
            {
                return ValueTask.FromCanceled(cancellationToken);
            }

            Recorded.Add(toolGatewayEvent.Type);
            return ValueTask.CompletedTask;
        }
    }
}
