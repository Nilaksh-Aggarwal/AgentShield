using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.Context;
using AgentShield.Application.Agents.AuthorizeAgentAction;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.UnitTests.Application.Agents;

/// <summary>
/// The authorize use case passes the request to the boundary unchanged, returns the boundary's verdict unchanged, and
/// records it in every sink before answering; a recording failure returns no decision.
/// </summary>
public sealed class AuthorizeAgentActionUseCaseTests
{
    private static readonly AuthorizeAgentActionRequest Request = new("support-agent", "email", "send", "email:send", SecurityDecision.Allow);

    private readonly StubAuthorizer _authorizer = new(Verdict(AgentActionReason.HumanApprovalRequired, RiskLevel.High));
    private readonly RecordingSink _sink = new();
    private readonly List<IAgentActionEventSink> _otherSinks = [];

    [Fact]
    public async Task ExecuteAsync_GivesTheBoundaryExactlyWhatTheAgentProposed()
    {
        await CreateUseCase().ExecuteAsync(Request, CancellationToken.None);

        var proposal = Assert.Single(_authorizer.Received);
        Assert.Equal("test-runtime", proposal.Caller);
        Assert.Equal(new AgentId("support-agent"), proposal.Agent);
        Assert.Equal(new ToolId("email"), proposal.Tool);
        Assert.Equal(new ActionName("send"), proposal.Action);
        Assert.Equal(new Capability("email:send"), proposal.Capability);
        Assert.Equal(SecurityDecision.Allow, proposal.InputDecision);
    }

    [Fact]
    public async Task ExecuteAsync_ReturnsTheBoundarysVerdictUnchanged_ForEveryReason()
    {
        foreach (var reason in Enum.GetValues<AgentActionReason>())
        {
            var authorizer = new StubAuthorizer(Verdict(reason, RiskLevel.Medium));

            var result = await CreateUseCase(authorizer).ExecuteAsync(Request, CancellationToken.None);

            Assert.True(result.IsSuccess);
            Assert.Equal(AgentActionReasons.DecisionFor(reason), result.Value.Decision);
            Assert.Equal((reason, RiskLevel.Medium), (result.Value.Reason, result.Value.RiskLevel));
        }
    }

    [Fact]
    public async Task ExecuteAsync_AnInputDecisionOfAllow_CannotLiftAReviewOrBlockVerdict()
    {
        // The agent reports the most permissive input decision; only the boundary's verdict is returned.
        foreach (var reason in new[] { AgentActionReason.HumanApprovalRequired, AgentActionReason.CapabilityNotGranted })
        {
            var result = await CreateUseCase(new StubAuthorizer(Verdict(reason, RiskLevel.High))).ExecuteAsync(Request, CancellationToken.None);

            Assert.NotEqual(SecurityDecision.Allow, result.Value.Decision);
        }
    }

    [Fact]
    public async Task ExecuteAsync_PublishesOneEventMatchingTheResponse_ToEverySink_AfterTheBoundaryDecided()
    {
        var second = new RecordingSink();
        _otherSinks.Add(second);
        _sink.OnPublish = _ => Assert.Single(_authorizer.Received);

        var result = await CreateUseCase().ExecuteAsync(Request, CancellationToken.None);

        var recorded = Assert.Single(_sink.Events);
        Assert.Same(recorded, Assert.Single(second.Events));
        Assert.Equal(result.Value.SecurityEventId, recorded.Id.Value);
        Assert.Same(_authorizer.Verdict, recorded.Authorization);
        Assert.Equal("corr-agent-test", recorded.CorrelationId);
        Assert.Equal(SecurityDecision.Allow, recorded.InputDecision);
        Assert.Equal(new DateTimeOffset(2026, 10, 7, 9, 0, 0, TimeSpan.Zero), recorded.OccurredAt);
    }

    [Fact]
    public async Task ExecuteAsync_ASinkFails_TheOtherSinksStillRecord_AndNoDecisionIsReturned()
    {
        var after = new RecordingSink();
        _otherSinks.Add(new FailingSink(new InvalidOperationException("store down")));
        _otherSinks.Add(after);

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(() => CreateUseCase().ExecuteAsync(Request, CancellationToken.None));

        Assert.Equal("store down", thrown.Message);
        Assert.Single(_sink.Events);
        Assert.Single(after.Events);
    }

    [Fact]
    public async Task ExecuteAsync_SeveralSinksFail_EveryFailureIsRaised()
    {
        _otherSinks.Add(new FailingSink(new InvalidOperationException("first")));
        _otherSinks.Add(new FailingSink(new TimeoutException("second")));

        var thrown = await Assert.ThrowsAsync<AggregateException>(() => CreateUseCase().ExecuteAsync(Request, CancellationToken.None));

        Assert.Equal(["first", "second"], thrown.InnerExceptions.Select(exception => exception.Message));
        Assert.Single(_sink.Events);
    }

    [Fact]
    public async Task ExecuteAsync_ASinkIsCancelled_EveryOtherSinkStillRecords_ThenTheCancellationPropagates()
    {
        // Milestone 13 (audit sink cancellation): a cancelled sink no longer skips the sinks after it, so a cancelled request
        // cannot leave the audit log and the activity history disagreeing about a decision that was made.
        var after = new RecordingSink();
        _otherSinks.Add(new FailingSink(new OperationCanceledException()));
        _otherSinks.Add(after);

        await Assert.ThrowsAsync<OperationCanceledException>(() => CreateUseCase().ExecuteAsync(Request, CancellationToken.None));

        Assert.Single(after.Events);
        Assert.Single(_sink.Events);
    }

    [Fact]
    public async Task ExecuteAsync_ASinkFailsAndAnotherIsCancelled_TheFailureWins_AfterEverySinkWasTried()
    {
        var after = new RecordingSink();
        _otherSinks.Add(new FailingSink(new OperationCanceledException()));
        _otherSinks.Add(new FailingSink(new InvalidOperationException("sink fault")));
        _otherSinks.Add(after);

        await Assert.ThrowsAsync<InvalidOperationException>(() => CreateUseCase().ExecuteAsync(Request, CancellationToken.None));

        Assert.Single(after.Events);
    }

    [Fact]
    public async Task ExecuteAsync_TheBoundaryThrows_NothingIsRecordedAndNoDecisionIsReturned()
    {
        var authorizer = new StubAuthorizer(Verdict(AgentActionReason.Permitted, RiskLevel.Low)) { Failure = new InvalidOperationException("boundary fault") };

        await Assert.ThrowsAsync<InvalidOperationException>(() => CreateUseCase(authorizer).ExecuteAsync(Request, CancellationToken.None));

        Assert.Empty(_sink.Events);
    }

    [Theory]
    [InlineData(null, "email", "send", "email:send")]
    [InlineData("support-agent", null, "send", "email:send")]
    [InlineData("support-agent", "email", null, "email:send")]
    [InlineData("support-agent", "email", "send", null)]
    [InlineData("Support-Agent", "email", "send", "email:send")]
    [InlineData("support-agent", "email", "send", "email:*")]
    public async Task ExecuteAsync_UnvalidatedRequest_NeverReachesTheBoundary(string? agentId, string? tool, string? action, string? capability)
    {
        var request = new AuthorizeAgentActionRequest(agentId, tool, action, capability, null);

        await Assert.ThrowsAnyAsync<ArgumentException>(() => CreateUseCase().ExecuteAsync(request, CancellationToken.None));

        Assert.Empty(_authorizer.Received);
        Assert.Empty(_sink.Events);
    }

    private AuthorizeAgentActionUseCase CreateUseCase(StubAuthorizer? authorizer = null) =>
        new(authorizer ?? _authorizer, [_sink, .. _otherSinks], new FixedCallerContext("test-runtime"), new FixedCorrelationContext("corr-agent-test"), new FixedTimeProvider());

    private static AgentActionAuthorization Verdict(AgentActionReason reason, RiskLevel risk)
    {
        var agent = new AgentId("support-agent");
        var tool = new ToolId("email");
        var recognised = reason switch
        {
            AgentActionReason.UnknownAgent => new RecognisedAgentAction(null, tool, new ActionName("send"), new Capability("email:send")),
            AgentActionReason.UnknownTool => new RecognisedAgentAction(agent, null, null, null),
            AgentActionReason.UnknownAction => new RecognisedAgentAction(agent, tool, null, null),
            _ => new RecognisedAgentAction(agent, tool, new ActionName("send"), new Capability("email:send")),
        };
        return new AgentActionAuthorization(reason, risk, recognised);
    }

    private sealed class StubAuthorizer(AgentActionAuthorization verdict) : IAgentActionAuthorizer
    {
        public AgentActionAuthorization Verdict { get; } = verdict;

        public Exception? Failure { get; init; }

        public List<AgentActionRequest> Received { get; } = [];

        public AgentActionAuthorization Authorize(AgentActionRequest request)
        {
            Received.Add(request);
            return Failure is null ? Verdict : throw Failure;
        }
    }

    private sealed class RecordingSink : IAgentActionEventSink
    {
        public List<AgentActionEvent> Events { get; } = [];

        public Action<AgentActionEvent>? OnPublish { get; set; }

        public ValueTask PublishAsync(AgentActionEvent agentActionEvent, CancellationToken cancellationToken)
        {
            OnPublish?.Invoke(agentActionEvent);
            Events.Add(agentActionEvent);
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FailingSink(Exception failure) : IAgentActionEventSink
    {
        public ValueTask PublishAsync(AgentActionEvent agentActionEvent, CancellationToken cancellationToken) => ValueTask.FromException(failure);
    }

    private sealed class FixedCallerContext(string clientId) : ICallerContext
    {
        public string ClientId { get; } = clientId;
    }

    private sealed class FixedCorrelationContext(string correlationId) : ICorrelationContext
    {
        public string CorrelationId { get; } = correlationId;
    }

    private sealed class FixedTimeProvider : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => new(2026, 10, 7, 9, 0, 0, TimeSpan.Zero);
    }
}
