using System.Text.Json;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Agents.ExecuteTool;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Infrastructure.Activity;
using AgentShield.Infrastructure.Agents;
using AgentShield.UnitTests.Infrastructure.AiCapacity;
using Microsoft.Extensions.Options;

namespace AgentShield.UnitTests.Application.Agents;

/// <summary>
/// The tool gateway's orchestration: the agent comes from the caller, the boundary decides first, only its Allow can reach
/// the argument policy and a grant, every stage is recorded before the next starts, and nothing the gateway can stop at
/// turns a Block or Review into an execution.
/// </summary>
public sealed class ToolGatewayTests
{
    private const string Runtime = "support-runtime";

    private static readonly AgentProfile Support = new(new AgentId("support-agent"), [new Capability("knowledge:read")], [Runtime, "other-runtime"], gatewayClient: Runtime);

    private readonly ScriptedAuthorizer _authorizer = new(ScriptedAuthorizer.For(AgentActionReason.Permitted, RiskLevel.Low));
    private readonly ScriptedArgumentPolicy _policy = new("knowledge", "lookup");
    private readonly ScriptedExecutionAuthority _authority = new();
    private readonly RecordingGatewaySink _sink = new();
    private readonly ManualClock _clock = new();
    private readonly InMemoryInputSecurityContextStore _inputs;
    private readonly InMemoryToolApprovalStore _approvals;

    public ToolGatewayTests()
    {
        _inputs = new InMemoryInputSecurityContextStore(_clock);
        _approvals = new InMemoryToolApprovalStore(Options.Create(new ToolApprovalOptions()), _clock);
    }

    [Fact]
    public async Task ExecuteAsync_Allow_RecordsRequestedAllowedStartedCompleted_ThenRunsOnce_AndReturnsTheResult()
    {
        var result = await Gateway().ExecuteAsync(Request(), CancellationToken.None);

        Assert.True(result.IsSuccess);
        var response = result.Value;
        Assert.Equal((SecurityDecision.Allow, true, ToolExecutionOutcome.Executed), (response.Decision, response.Executed, response.Outcome));
        Assert.Equal((AgentActionReason.Permitted, RiskLevel.Low), (response.AuthorizationReason, response.RiskLevel));
        Assert.Equal(new ToolResultResponse(true, "Dependency injection: the composition root chooses."), response.Result);

        Assert.Equal(
            [ToolGatewayEventType.ToolAuthorizationRequested, ToolGatewayEventType.ToolAuthorizationAllowed, ToolGatewayEventType.ToolExecutionStarted, ToolGatewayEventType.ToolExecutionCompleted],
            _sink.Types);
        var execution = Assert.Single(_authority.Executions);
        var grant = Assert.Single(_authority.Grants);
        Assert.Same(grant, execution.Grant);
        Assert.Equal(grant.ExecutionId, response.ExecutionId);
        Assert.All(_sink.Entries, entry => Assert.Equal(response.SecurityEventId, entry.Id.Value));
        Assert.Equal(1, _policy.Checks);
    }

    [Fact]
    public async Task ExecuteAsync_TheAgentComesFromTheCaller_AndTheBoundaryGetsExactlyTheRequest()
    {
        await Gateway().ExecuteAsync(Request(inputDecision: SecurityDecision.Review), CancellationToken.None);

        var proposal = Assert.Single(_authorizer.Received);
        Assert.Equal((Runtime, new AgentId("support-agent")), (proposal.Caller, proposal.Agent));
        Assert.Equal((new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read")), (proposal.Tool, proposal.Action, proposal.Capability));
        Assert.Equal(SecurityDecision.Review, proposal.InputDecision);
        Assert.Same(proposal, Assert.Single(_authority.Issued).Request);
        Assert.Equal(new AgentId("support-agent"), _sink.Entries[0].Agent);
    }

    [Fact]
    public async Task ExecuteAsync_TheCallPresented_IsBuiltFromTheRequest_AndMatchesTheGrantsScope()
    {
        await Gateway(correlationId: "corr-scope").ExecuteAsync(Request(), CancellationToken.None);

        var (grant, call) = Assert.Single(_authority.Executions);
        Assert.Equal(grant.Scope, call.Scope);
        Assert.Equal("corr-scope", call.Scope.CorrelationId);
        Assert.Equal(_sink.Entries[0].Id, call.Scope.SecurityEventId);
        Assert.IsType<KnowledgeLookupArguments>(call.Arguments);
        var issued = Assert.Single(_authority.Issued);
        Assert.Equal((_sink.Entries[0].Id, "corr-scope"), (issued.SecurityEventId, issued.CorrelationId));
    }

    [Theory]
    [InlineData(AgentActionReason.HumanApprovalRequired, ToolExecutionOutcome.HeldForReview, SecurityDecision.Review, ToolGatewayEventType.ToolAuthorizationReviewed)]
    [InlineData(AgentActionReason.InputHeldForReview, ToolExecutionOutcome.HeldForReview, SecurityDecision.Review, ToolGatewayEventType.ToolAuthorizationReviewed)]
    [InlineData(AgentActionReason.CapabilityNotGranted, ToolExecutionOutcome.Denied, SecurityDecision.Block, ToolGatewayEventType.ToolAuthorizationBlocked)]
    [InlineData(AgentActionReason.CriticalActionDenied, ToolExecutionOutcome.Denied, SecurityDecision.Block, ToolGatewayEventType.ToolAuthorizationBlocked)]
    [InlineData(AgentActionReason.InputBlocked, ToolExecutionOutcome.Denied, SecurityDecision.Block, ToolGatewayEventType.ToolAuthorizationBlocked)]
    [InlineData(AgentActionReason.CapabilityMismatch, ToolExecutionOutcome.Denied, SecurityDecision.Block, ToolGatewayEventType.ToolAuthorizationBlocked)]
    public async Task ExecuteAsync_ReviewOrBlock_NeverChecksArguments_IssuesAGrant_OrRunsTheTool(
        AgentActionReason reason, ToolExecutionOutcome outcome, SecurityDecision decision, ToolGatewayEventType refused)
    {
        _authorizer.Verdict = ScriptedAuthorizer.For(reason, RiskLevel.High);

        var response = (await Gateway().ExecuteAsync(Request(), CancellationToken.None)).Value;

        Assert.Equal((decision, false, outcome, reason), (response.Decision, response.Executed, response.Outcome, response.AuthorizationReason));
        Assert.Null(response.ExecutionId);
        Assert.Null(response.Result);
        Assert.Equal([ToolGatewayEventType.ToolAuthorizationRequested, refused, ToolGatewayEventType.ToolExecutionRejected], _sink.Types);
        Assert.Empty(_authority.Issued);
        Assert.Empty(_authority.Executions);
        Assert.Equal(0, _policy.Checks);
    }

    [Fact]
    public async Task ExecuteAsync_EveryNonAllowReason_IsReturnedAsTheBoundaryDecidedIt_WithoutExecution()
    {
        foreach (var reason in Enum.GetValues<AgentActionReason>().Where(reason => AgentActionReasons.DecisionFor(reason) != SecurityDecision.Allow))
        {
            var authority = new ScriptedExecutionAuthority();
            var recognised = reason is AgentActionReason.UnknownAgent or AgentActionReason.UnknownTool or AgentActionReason.UnknownAction
                ? new RecognisedAgentAction(reason == AgentActionReason.UnknownAgent ? null : new AgentId("support-agent"), null, null, null)
                : ScriptedAuthorizer.For(AgentActionReason.Permitted, RiskLevel.Low).Recognised;
            var authorizer = new ScriptedAuthorizer(new AgentActionAuthorization(reason, RiskLevel.Critical, recognised));

            var response = (await Gateway(authorizer: authorizer, authority: authority).ExecuteAsync(Request(), CancellationToken.None)).Value;

            Assert.Equal(AgentActionReasons.DecisionFor(reason), response.Decision);
            Assert.False(response.Executed);
            Assert.Empty(authority.Issued);
            Assert.Empty(authority.Executions);
        }
    }

    [Fact]
    public async Task ExecuteAsync_AnAllowedActionWithoutAnExecutableTool_IsBlocked_WithoutAGrant()
    {
        var response = (await Gateway(policies: [new ScriptedArgumentPolicy("data", "read")]).ExecuteAsync(Request(), CancellationToken.None)).Value;

        Assert.Equal((SecurityDecision.Block, false, ToolExecutionOutcome.ToolUnavailable, AgentActionReason.Permitted), (response.Decision, response.Executed, response.Outcome, response.AuthorizationReason));
        Assert.Equal([ToolGatewayEventType.ToolAuthorizationRequested, ToolGatewayEventType.ToolAuthorizationBlocked, ToolGatewayEventType.ToolExecutionRejected], _sink.Types);
        Assert.Empty(_authority.Issued);
        Assert.Empty(_authority.Executions);
    }

    [Fact]
    public async Task ExecuteAsync_APolicyMatchingOnlyTheToolOrOnlyTheAction_IsNotTheActionsPolicy()
    {
        // knowledge.search and data.lookup share a part with knowledge.lookup; neither is its policy.
        var sameTool = new ScriptedArgumentPolicy("knowledge", "search");
        var sameAction = new ScriptedArgumentPolicy("data", "lookup");

        var response = (await Gateway(policies: [sameTool, sameAction]).ExecuteAsync(Request(), CancellationToken.None)).Value;

        Assert.Equal(ToolExecutionOutcome.ToolUnavailable, response.Outcome);
        Assert.Equal((0, 0), (sameTool.Checks, sameAction.Checks));
        Assert.Empty(_authority.Issued);
    }

    [Theory]
    [InlineData(ToolArgumentViolation.UnexpectedArgument)]
    [InlineData(ToolArgumentViolation.TooLong)]
    [InlineData(ToolArgumentViolation.WrongType)]
    public async Task ExecuteAsync_ArgumentsThePolicyRejects_AreBlocked_WithoutAGrant_AndTheViolationIsAuditedOnly(ToolArgumentViolation violation)
    {
        var response = (await Gateway(policies: [new ScriptedArgumentPolicy("knowledge", "lookup", violation)]).ExecuteAsync(Request(), CancellationToken.None)).Value;

        Assert.Equal((SecurityDecision.Block, false, ToolExecutionOutcome.ArgumentsRejected), (response.Decision, response.Executed, response.Outcome));
        Assert.Null(response.ExecutionId);
        Assert.Empty(_authority.Issued);
        Assert.Empty(_authority.Executions);
        Assert.All(_sink.Entries.Skip(1), entry => Assert.Equal(violation, entry.ArgumentViolation));
        Assert.DoesNotContain(violation.ToString(), JsonSerializer.Serialize(response), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(ExecutionGrantRejection.Expired)]
    [InlineData(ExecutionGrantRejection.AlreadyUsed)]
    [InlineData(ExecutionGrantRejection.InvalidSignature)]
    [InlineData(ExecutionGrantRejection.WrongTool)]
    [InlineData(ExecutionGrantRejection.NoExecutor)]
    public async Task ExecuteAsync_AGrantTheAuthorityRefuses_IsABlock_AndNothingRan(ExecutionGrantRejection rejection)
    {
        _authority.RefuseWith = rejection;

        var response = (await Gateway().ExecuteAsync(Request(), CancellationToken.None)).Value;

        Assert.Equal((SecurityDecision.Block, false, ToolExecutionOutcome.ExecutionAuthorizationRejected), (response.Decision, response.Executed, response.Outcome));
        Assert.Equal(_authority.Grants.Single().ExecutionId, response.ExecutionId);
        Assert.Null(response.Result);
        Assert.Equal(
            [ToolGatewayEventType.ToolAuthorizationRequested, ToolGatewayEventType.ToolAuthorizationAllowed, ToolGatewayEventType.ToolExecutionStarted, ToolGatewayEventType.ToolExecutionRejected],
            _sink.Types);
        Assert.Equal(rejection, _sink.Entries[^1].GrantRejection);
        Assert.DoesNotContain(rejection.ToString(), JsonSerializer.Serialize(response), StringComparison.Ordinal);
    }

    [Fact]
    public async Task ExecuteAsync_TheAuthorityIssuesNoGrantForAnAllow_FailsWithoutExecutingOrRecordingAnAllow()
    {
        _authority.IssueNothing = true;

        await Assert.ThrowsAsync<InvalidOperationException>(() => Gateway().ExecuteAsync(Request(), CancellationToken.None));

        Assert.Empty(_authority.Executions);
        Assert.Equal([ToolGatewayEventType.ToolAuthorizationRequested], _sink.Types);
    }

    [Fact]
    public async Task ExecuteAsync_TheToolFails_IsRecordedAsFailed_AndTheFailurePropagates_WithoutAResult()
    {
        var failure = new InvalidOperationException("tool failure (test)");
        _authority.ThrowOnExecute = failure;

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(() => Gateway().ExecuteAsync(Request(), CancellationToken.None));

        Assert.Same(failure, thrown);
        Assert.Equal(ToolGatewayEventType.ToolExecutionFailed, _sink.Types.Last());
        Assert.Equal(ToolExecutionOutcome.ExecutionFailed, _sink.Entries[^1].Outcome);
    }

    [Fact]
    public async Task ExecuteAsync_TheToolFails_AndRecordingTheFailureFails_RaisesBoth()
    {
        var toolFailure = new InvalidOperationException("tool failure (test)");
        var recordingFailure = new InvalidOperationException("recording failure (test)");
        _authority.ThrowOnExecute = toolFailure;
        var failingSink = new RecordingGatewaySink(ToolGatewayEventType.ToolExecutionFailed, recordingFailure);

        var thrown = await Assert.ThrowsAsync<AggregateException>(() => Gateway(sinks: [failingSink]).ExecuteAsync(Request(), CancellationToken.None));

        Assert.Equal([toolFailure, recordingFailure], thrown.InnerExceptions);
    }

    [Fact]
    public async Task ExecuteAsync_ACancelledToolCall_IsRecordedAsFailed_ThenTheCancellationPropagates()
    {
        // D-21: the grant was consumed and the tool may have run, so the request still gets its last entry.
        _authority.ThrowOnExecute = new OperationCanceledException();

        await Assert.ThrowsAsync<OperationCanceledException>(() => Gateway().ExecuteAsync(Request(), CancellationToken.None));

        Assert.Equal(ToolGatewayEventType.ToolExecutionFailed, _sink.Types.Last());
        Assert.Equal(ToolExecutionOutcome.ExecutionFailed, _sink.Entries[^1].Outcome);
    }

    [Fact]
    public async Task ExecuteAsync_TheRequestIsCancelledDuringTheTool_TheFailureIsStillRecorded_NotSkippedByTheCancelledToken()
    {
        using var request = new CancellationTokenSource();
        var authority = new CancellingAuthority(request);
        var sink = new TokenHonouringSink();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Gateway(authority: authority, sinks: [sink]).ExecuteAsync(Request(), request.Token));

        Assert.Equal(
            [ToolGatewayEventType.ToolAuthorizationRequested, ToolGatewayEventType.ToolAuthorizationAllowed, ToolGatewayEventType.ToolExecutionStarted, ToolGatewayEventType.ToolExecutionFailed],
            sink.Recorded);
    }

    [Theory]
    [InlineData(ToolGatewayEventType.ToolAuthorizationRequested, 0, 0)]
    [InlineData(ToolGatewayEventType.ToolAuthorizationAllowed, 1, 0)]
    [InlineData(ToolGatewayEventType.ToolExecutionStarted, 1, 0)]
    [InlineData(ToolGatewayEventType.ToolExecutionCompleted, 1, 1)]
    public async Task ExecuteAsync_ASinkFailsAtAStage_EverySinkStillRecordsIt_AndTheGatewayGoesNoFurther(ToolGatewayEventType stage, int grants, int executions)
    {
        var failing = new RecordingGatewaySink(stage);
        var after = new RecordingGatewaySink();

        await Assert.ThrowsAsync<InvalidOperationException>(() => Gateway(sinks: [failing, after]).ExecuteAsync(Request(), CancellationToken.None));

        // A grant is never issued before the request was recorded, and the tool never runs before its start was recorded.
        Assert.Equal(grants, _authority.Grants.Count);
        Assert.Equal(executions, _authority.Executions.Count);
        Assert.Equal(stage, failing.Types.Last());
        Assert.Equal(failing.Types, after.Types);
    }

    [Fact]
    public async Task ExecuteAsync_SeveralSinksFail_EveryFailureIsRaised()
    {
        var first = new InvalidOperationException("first (test)");
        var second = new InvalidOperationException("second (test)");

        var thrown = await Assert.ThrowsAsync<AggregateException>(() => Gateway(sinks:
        [
            new RecordingGatewaySink(ToolGatewayEventType.ToolAuthorizationRequested, first),
            new RecordingGatewaySink(ToolGatewayEventType.ToolAuthorizationRequested, second),
        ]).ExecuteAsync(Request(), CancellationToken.None));

        Assert.Equal([first, second], thrown.InnerExceptions);
        Assert.Empty(_authority.Issued);
    }

    [Fact]
    public async Task ExecuteAsync_ACallerThatIsNoAgentsGatewayIdentity_Fails_BeforeAnythingIsAskedOrRecorded()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() => Gateway(caller: "other-runtime").ExecuteAsync(Request(), CancellationToken.None));

        Assert.Empty(_authorizer.Received);
        Assert.Empty(_sink.Entries);
    }

    [Fact]
    public async Task ExecuteAsync_ALookupAnsweringForAnotherCaller_IsNotTrusted()
    {
        // "other-runtime" is bound to the agent, but is not its gateway identity: a lenient directory must not make it one.
        var directory = new GatewayDirectory([Support], lenient: true);

        await Assert.ThrowsAsync<InvalidOperationException>(() => Gateway(caller: "other-runtime", directory: directory).ExecuteAsync(Request(), CancellationToken.None));

        Assert.Empty(_authorizer.Received);
    }

    [Fact]
    public async Task ExecuteAsync_TwoArgumentPoliciesForOneAction_IsAnError_NotAChoice()
    {
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            Gateway(policies: [new ScriptedArgumentPolicy("knowledge", "lookup"), new ScriptedArgumentPolicy("knowledge", "lookup")]).ExecuteAsync(Request(), CancellationToken.None));

        Assert.Empty(_authority.Issued);
    }

    [Fact]
    public async Task ExecuteAsync_AnUnvalidatedRequest_FailsBeforeTheBoundary()
    {
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Gateway().ExecuteAsync(Request() with { Tool = null }, CancellationToken.None));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Gateway().ExecuteAsync(Request() with { Capability = "Not A Capability" }, CancellationToken.None));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Gateway().ExecuteAsync(Request() with { Arguments = null }, CancellationToken.None));
        await Assert.ThrowsAnyAsync<ArgumentException>(() => Gateway().ExecuteAsync(Request(arguments: "[]"), CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentNullException>(() => Gateway().ExecuteAsync(null!, CancellationToken.None));

        Assert.Empty(_authorizer.Received);
        Assert.Empty(_sink.Entries);
    }

    [Fact]
    public async Task ExecuteAsync_ACancelledRequest_StopsBeforeTheBoundary()
    {
        using var cancelled = new CancellationTokenSource();
        await cancelled.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => Gateway(sinks: [new CancellingSink()]).ExecuteAsync(Request(), cancelled.Token));

        Assert.Empty(_authorizer.Received);
    }

    [Fact]
    public async Task ExecuteAsync_TheResponse_NeverEchoesTheArguments()
    {
        const string Marker = "zq7gwunit";
        var response = (await Gateway().ExecuteAsync(Request(arguments: $$"""{"query":"{{Marker}}"}"""), CancellationToken.None)).Value;

        Assert.DoesNotContain(Marker, JsonSerializer.Serialize(response), StringComparison.Ordinal);
        Assert.All(_sink.Entries, entry => Assert.DoesNotContain(Marker, entry.ToString(), StringComparison.Ordinal));
    }

    [Fact]
    public async Task ExecuteAsync_ElapsedTime_ComesFromTheClock()
    {
        var authority = new AdvancingAuthority(_clock, TimeSpan.FromMilliseconds(250));

        await Gateway(authority: authority).ExecuteAsync(Request(), CancellationToken.None);

        Assert.Equal(TimeSpan.FromMilliseconds(250), _sink.Entries[^1].Elapsed);
        Assert.Equal(ManualClock.Start, _sink.Entries[0].OccurredAt);
        Assert.Equal(ManualClock.Start.AddMilliseconds(250), _sink.Entries[^1].OccurredAt);
    }

    private ToolGateway Gateway(
        string caller = Runtime,
        string correlationId = "corr-gateway",
        GatewayDirectory? directory = null,
        ScriptedAuthorizer? authorizer = null,
        IToolArgumentPolicy[]? policies = null,
        IToolExecutionAuthority? authority = null,
        IToolGatewayEventSink[]? sinks = null) =>
        new(
            new FixedCaller(caller),
            new FixedCorrelation(correlationId),
            directory ?? new GatewayDirectory([Support]),
            authorizer ?? _authorizer,
            policies ?? [_policy],
            authority ?? _authority,
            _inputs,
            _approvals,
            sinks ?? [_sink],
            _clock);

    private static ExecuteToolRequest Request(string arguments = """{"query":"dependency injection"}""", SecurityDecision? inputDecision = null)
    {
        using var document = JsonDocument.Parse(arguments);
        return new ExecuteToolRequest("knowledge", "lookup", "knowledge:read", document.RootElement.Clone(), inputDecision);
    }

    /// <summary>Honours cancellation like a real sink would.</summary>
    private sealed class CancellingSink : IToolGatewayEventSink
    {
        public ValueTask PublishAsync(ToolGatewayEvent toolGatewayEvent, CancellationToken cancellationToken) =>
            cancellationToken.IsCancellationRequested ? ValueTask.FromCanceled(cancellationToken) : ValueTask.CompletedTask;
    }

    /// <summary>Cancels the request while the tool runs, as a client that disconnects would.</summary>
    private sealed class CancellingAuthority(CancellationTokenSource request) : IToolExecutionAuthority
    {
        private readonly ScriptedExecutionAuthority _inner = new();

        public ExecutionGrant? Issue(AgentActionRequest proposal, SecurityEventId securityEventId, string correlationId, Guid? approvalId = null) =>
            _inner.Issue(proposal, securityEventId, correlationId, approvalId);

        public async ValueTask<ToolExecutionAttempt> ExecuteAsync(ExecutionGrant grant, ToolCall call, CancellationToken cancellationToken)
        {
            await request.CancelAsync();
            cancellationToken.ThrowIfCancellationRequested();
            return ToolExecutionAttempt.Ran(new ToolOutput(found: false, text: null));
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

    /// <summary>Takes some time to run the tool.</summary>
    private sealed class AdvancingAuthority(ManualClock clock, TimeSpan duration) : IToolExecutionAuthority
    {
        private readonly ScriptedExecutionAuthority _inner = new();

        public ExecutionGrant? Issue(AgentActionRequest request, SecurityEventId securityEventId, string correlationId, Guid? approvalId = null) =>
            _inner.Issue(request, securityEventId, correlationId, approvalId);

        public ValueTask<ToolExecutionAttempt> ExecuteAsync(ExecutionGrant grant, ToolCall call, CancellationToken cancellationToken)
        {
            clock.Advance(duration);
            return _inner.ExecuteAsync(grant, call, cancellationToken);
        }
    }
}
