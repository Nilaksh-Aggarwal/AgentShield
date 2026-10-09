using System.Collections.Concurrent;
using System.Reflection;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Domain.Policy;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Security.Agents;
using AgentShield.Security.ToolGateway;
using AgentShield.SecurityTests.Agents;
using AgentShield.SecurityTests.AiAnalysis;

namespace AgentShield.SecurityTests.ToolGateway;

/// <summary>
/// The execution authority (adversarial): a grant exists only for what the real authorization boundary allows, cannot be
/// made up or altered, runs exactly the call it was issued for, once, before it expires — and nothing else ever runs a tool.
/// </summary>
public sealed class ExecutionGrantAuthorityTests
{
    private const string Runtime = "gateway-runtime";

    private static readonly InMemoryAgentDirectory Agents = new(
        new AgentProfile(new AgentId("gateway-agent"), Capabilities("knowledge:read", "data:read", "data:write", "email:send", "payment:execute"), [Runtime], Runtime),
        new AgentProfile(new AgentId("other-agent"), Capabilities("knowledge:read"), ["other-runtime"], "other-runtime"));

    private static readonly AgentActionAuthorizer Authorizer = new(new ReferenceToolCatalog(), Agents);

    private readonly ManualTimeProvider _clock = new();
    private readonly TestApprovalStore _approvals = new();
    private readonly CountingExecutor _knowledge = new("knowledge", "lookup");
    private readonly CountingExecutor _write = new("data", "write");

    [Fact]
    public void Issue_AnAllowedAction_IsAGrantForExactlyThatAction_ValidFor30Seconds()
    {
        var authority = Authority();
        var eventId = SecurityEventId.New();

        var grant = authority.Issue(Request("knowledge", "lookup", "knowledge:read"), eventId, "corr-issue");

        Assert.NotNull(grant);
        Assert.Equal(new ExecutionScope(eventId, "corr-issue", new AgentId("gateway-agent"), new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read")), grant.Scope);
        Assert.Equal((_clock.GetUtcNow(), _clock.GetUtcNow().AddSeconds(30)), (grant.IssuedAt, grant.ExpiresAt));
        Assert.Equal(TimeSpan.FromSeconds(30), ExecutionGrantAuthority.Lifetime);
        Assert.Matches("^[0-9a-f]{64}$", grant.Signature);
        Assert.Equal(7, grant.ExecutionId.Version);
        Assert.Equal(1, authority.OutstandingCount);
    }

    [Theory]
    [InlineData("email", "send", "email:send", null)]
    [InlineData("payment", "execute", "payment:execute", null)]
    [InlineData("knowledge", "lookup", "data:read", null)]
    [InlineData("knowledge", "lookup", "knowledge:read", SecurityDecision.Review)]
    [InlineData("knowledge", "lookup", "knowledge:read", SecurityDecision.Block)]
    [InlineData("shell", "exec", "shell:exec", null)]
    [InlineData("knowledge", "delete", "knowledge:read", null)]
    [InlineData("secrets", "read", "secrets:read", null)]
    public void Issue_NothingTheBoundaryDoesNotAllow_EverGetsAGrant(string tool, string action, string capability, SecurityDecision? input)
    {
        var authority = Authority();

        Assert.Null(authority.Issue(Request(tool, action, capability, input), SecurityEventId.New(), "corr"));
        Assert.Equal(0, authority.OutstandingCount);
    }

    [Fact]
    public void Issue_TheAuthorityAsksTheBoundaryItself_NotTheCallersVerdict()
    {
        // A caller that claims an Allow it never got: "other-runtime" acting as gateway-agent is not bound to it.
        var authority = Authority();

        Assert.Null(authority.Issue(Request("knowledge", "lookup", "knowledge:read", caller: "other-runtime"), SecurityEventId.New(), "corr"));
        var denying = new ExecutionGrantAuthority(new AlwaysBlock(), _approvals, [_knowledge], _clock);
        Assert.Null(denying.Issue(Request("knowledge", "lookup", "knowledge:read"), SecurityEventId.New(), "corr"));
    }

    [Fact]
    public void Issue_EveryNonAllowOverTheWholeCatalogue_GetsNoGrant()
    {
        var authority = Authority();
        var catalogue = new ReferenceToolCatalog();
        var issued = 0;
        foreach (var definition in catalogue.Actions)
        {
            foreach (SecurityDecision? input in new SecurityDecision?[] { null, SecurityDecision.Allow, SecurityDecision.Review, SecurityDecision.Block })
            {
                var request = new AgentActionRequest(Runtime, new AgentId("gateway-agent"), definition.Tool, definition.Action, definition.RequiredCapability, input);
                var grant = authority.Issue(request, SecurityEventId.New(), "corr");
                Assert.Equal(Authorizer.Authorize(request).Decision == SecurityDecision.Allow, grant is not null);
                issued += grant is null ? 0 : 1;
            }
        }

        // knowledge.lookup, data.read, data.describe and data.write are allowed, with no input decision or Allow.
        Assert.Equal(8, issued);
    }

    [Fact]
    public async Task ExecuteAsync_TheGrantsOwnCall_RunsTheToolOnce_AndReturnsItsOutput()
    {
        var authority = Authority();
        var (grant, call) = Issue(authority);

        var attempt = await authority.ExecuteAsync(grant, call, CancellationToken.None);

        Assert.True(attempt.Executed);
        Assert.Null(attempt.Rejection);
        Assert.Same(CountingExecutor.Output, attempt.Output);
        Assert.Equal(1, _knowledge.Calls);
        Assert.Same(call.Arguments, Assert.Single(_knowledge.Received));
        Assert.Equal(0, authority.OutstandingCount);
    }

    [Fact]
    public async Task ExecuteAsync_AGrantPresentedTwice_RunsOnce()
    {
        var authority = Authority();
        var (grant, call) = Issue(authority);

        await authority.ExecuteAsync(grant, call, CancellationToken.None);
        var replay = await authority.ExecuteAsync(grant, call, CancellationToken.None);
        var copy = await authority.ExecuteAsync(grant with { }, call, CancellationToken.None);

        Assert.Equal(ExecutionGrantRejection.AlreadyUsed, replay.Rejection);
        Assert.Equal(ExecutionGrantRejection.AlreadyUsed, copy.Rejection);
        Assert.Equal(1, _knowledge.Calls);
    }

    [Fact]
    public async Task ExecuteAsync_ConcurrentPresentations_ExactlyOneRuns()
    {
        var authority = Authority();
        var (grant, call) = Issue(authority);

        var attempts = await Task.WhenAll(Enumerable.Range(0, 64).Select(_ => Task.Run(async () => await authority.ExecuteAsync(grant, call, CancellationToken.None))));

        Assert.Single(attempts, attempt => attempt.Executed);
        Assert.All(attempts.Where(attempt => !attempt.Executed), attempt => Assert.Equal(ExecutionGrantRejection.AlreadyUsed, attempt.Rejection));
        Assert.Equal(1, _knowledge.Calls);
    }

    [Fact]
    public async Task ExecuteAsync_AnExpiredGrant_RunsNothing_AndIsGoneFromTheLedger()
    {
        var authority = Authority();
        var (grant, call) = Issue(authority);

        _clock.Advance(TimeSpan.FromSeconds(30));
        var attempt = await authority.ExecuteAsync(grant, call, CancellationToken.None);

        Assert.Equal(ExecutionGrantRejection.Expired, attempt.Rejection);
        Assert.Equal(0, _knowledge.Calls);
        Assert.Equal(0, authority.OutstandingCount);
        Assert.Equal(ExecutionGrantRejection.Expired, (await authority.ExecuteAsync(grant, call, CancellationToken.None)).Rejection);
    }

    [Fact]
    public async Task ExecuteAsync_AGrantJustBeforeItsExpiry_Runs()
    {
        var authority = Authority();
        var (grant, call) = Issue(authority);

        _clock.Advance(TimeSpan.FromSeconds(30) - TimeSpan.FromTicks(1));

        Assert.True((await authority.ExecuteAsync(grant, call, CancellationToken.None)).Executed);
    }

    [Fact]
    public async Task ExecuteAsync_AGrantForAnotherCall_RunsNothing_AndIsBurnt()
    {
        (string Name, Func<ExecutionScope, ExecutionScope> Change, ExecutionGrantRejection Expected)[] cases =
        [
            ("agent", scope => With(scope, agent: new AgentId("other-agent")), ExecutionGrantRejection.WrongAgent),
            ("tool", scope => With(scope, tool: new ToolId("data")), ExecutionGrantRejection.WrongTool),
            ("action", scope => With(scope, action: new ActionName("search")), ExecutionGrantRejection.WrongAction),
            ("capability", scope => With(scope, capability: new Capability("data:read")), ExecutionGrantRejection.WrongCapability),
            ("security event", scope => With(scope, securityEventId: SecurityEventId.New()), ExecutionGrantRejection.WrongRequest),
            ("correlation", scope => With(scope, correlationId: scope.CorrelationId + "-other"), ExecutionGrantRejection.WrongRequest),
        ];

        foreach (var (name, change, expected) in cases)
        {
            var authority = Authority();
            var (grant, call) = Issue(authority);

            var attempt = await authority.ExecuteAsync(grant, new ToolCall(change(call.Scope), call.Arguments), CancellationToken.None);
            var honestAfterwards = await authority.ExecuteAsync(grant, call, CancellationToken.None);

            Assert.True(expected == attempt.Rejection, $"{name}: {attempt.Rejection}");
            Assert.Equal(ExecutionGrantRejection.AlreadyUsed, honestAfterwards.Rejection);
        }

        Assert.Equal(0, _knowledge.Calls);
        Assert.Equal(0, _write.Calls);
    }

    [Fact]
    public async Task ExecuteAsync_AGrantForKnowledgeLookup_CannotRunAnotherTool()
    {
        // The executor is chosen by the call, after the grant was checked against it: a lookup grant never reaches data.write.
        var authority = Authority();
        var (grant, call) = Issue(authority);
        var writeScope = With(call.Scope, tool: new ToolId("data"), action: new ActionName("write"), capability: new Capability("data:write"));

        var attempt = await authority.ExecuteAsync(grant, new ToolCall(writeScope, call.Arguments), CancellationToken.None);

        Assert.Equal(ExecutionGrantRejection.WrongTool, attempt.Rejection);
        Assert.Equal((0, 0), (_knowledge.Calls, _write.Calls));
    }

    [Fact]
    public async Task ExecuteAsync_AnAlteredGrant_IsRefused_WithoutTouchingTheRealOne()
    {
        (string Name, Func<ExecutionGrant, ExecutionGrant> Alter)[] alterations =
        [
            ("execution ID", grant => new ExecutionGrant(Guid.CreateVersion7(), grant.Scope, grant.IssuedAt, grant.ExpiresAt, grant.Signature)),
            ("agent", grant => Rescope(grant, With(grant.Scope, agent: new AgentId("other-agent")))),
            ("tool", grant => Rescope(grant, With(grant.Scope, tool: new ToolId("data")))),
            ("action", grant => Rescope(grant, With(grant.Scope, action: new ActionName("write")))),
            ("capability", grant => Rescope(grant, With(grant.Scope, capability: new Capability("data:write")))),
            ("security event", grant => Rescope(grant, With(grant.Scope, securityEventId: SecurityEventId.New()))),
            ("correlation", grant => Rescope(grant, With(grant.Scope, correlationId: "corr-forged"))),
            ("issued at", grant => new ExecutionGrant(grant.ExecutionId, grant.Scope, grant.IssuedAt.AddTicks(1), grant.ExpiresAt, grant.Signature)),
            ("expiry extended", grant => new ExecutionGrant(grant.ExecutionId, grant.Scope, grant.IssuedAt, grant.ExpiresAt.AddHours(1), grant.Signature)),
            ("signature flipped", grant => new ExecutionGrant(grant.ExecutionId, grant.Scope, grant.IssuedAt, grant.ExpiresAt, Flip(grant.Signature))),
            ("signature truncated", grant => new ExecutionGrant(grant.ExecutionId, grant.Scope, grant.IssuedAt, grant.ExpiresAt, grant.Signature[..62])),
            ("signature not hex", grant => new ExecutionGrant(grant.ExecutionId, grant.Scope, grant.IssuedAt, grant.ExpiresAt, new string('z', 64))),
            ("signature made up", grant => new ExecutionGrant(grant.ExecutionId, grant.Scope, grant.IssuedAt, grant.ExpiresAt, new string('0', 64))),
        ];

        foreach (var (name, alter) in alterations)
        {
            var authority = Authority();
            var (grant, call) = Issue(authority);
            var altered = alter(grant);

            var forged = await authority.ExecuteAsync(altered, new ToolCall(altered.Scope, call.Arguments), CancellationToken.None);

            Assert.True(forged.Rejection == ExecutionGrantRejection.InvalidSignature, $"{name}: {forged.Rejection}");
            Assert.Equal(0, _knowledge.Calls + _write.Calls);
            Assert.True((await authority.ExecuteAsync(grant, call, CancellationToken.None)).Executed, $"{name}: the real grant was consumed by a forgery");
            _knowledge.Reset();
        }
    }

    [Fact]
    public async Task ExecuteAsync_AGrantFromAnotherAuthority_IsRefused()
    {
        // Each authority (each process) has its own key: a grant signed elsewhere is not one of its own.
        var issuer = Authority();
        var verifier = Authority();
        var (grant, call) = Issue(issuer);

        Assert.Equal(ExecutionGrantRejection.InvalidSignature, (await verifier.ExecuteAsync(grant, call, CancellationToken.None)).Rejection);
        Assert.Equal(0, _knowledge.Calls);
    }

    [Fact]
    public async Task ExecuteAsync_AValidGrantWithoutAnExecutor_RunsNothing_AndIsConsumed()
    {
        var authority = Authority();
        var request = Request("data", "read", "data:read");
        var eventId = SecurityEventId.New();
        var grant = authority.Issue(request, eventId, "corr")!;
        var call = new ToolCall(grant.Scope, new KnowledgeLookupArguments("x"));

        Assert.Equal(ExecutionGrantRejection.NoExecutor, (await authority.ExecuteAsync(grant, call, CancellationToken.None)).Rejection);
        Assert.Equal(ExecutionGrantRejection.AlreadyUsed, (await authority.ExecuteAsync(grant, call, CancellationToken.None)).Rejection);
        Assert.Equal((0, 0), (_knowledge.Calls, _write.Calls));
    }

    [Fact]
    public async Task ExecuteAsync_AFailingTool_Propagates_AndTheGrantStaysConsumed()
    {
        var failing = new CountingExecutor("knowledge", "lookup") { Failure = new InvalidOperationException("tool failure (test)") };
        var authority = new ExecutionGrantAuthority(Authorizer, _approvals, [failing], _clock);
        var (grant, call) = Issue(authority);

        await Assert.ThrowsAsync<InvalidOperationException>(async () => await authority.ExecuteAsync(grant, call, CancellationToken.None));

        Assert.Equal(ExecutionGrantRejection.AlreadyUsed, (await authority.ExecuteAsync(grant, call, CancellationToken.None)).Rejection);
        Assert.Equal(1, failing.Calls);
    }

    [Fact]
    public void Issue_TheLedgerIsBounded_AndExpiredGrantsArePurged()
    {
        var authority = Authority();
        for (var index = 0; index < ExecutionGrantAuthority.MaxOutstandingGrants; index++)
        {
            Assert.NotNull(authority.Issue(Request("knowledge", "lookup", "knowledge:read"), SecurityEventId.New(), "corr"));
        }

        Assert.Throws<InvalidOperationException>(() => authority.Issue(Request("knowledge", "lookup", "knowledge:read"), SecurityEventId.New(), "corr"));

        _clock.Advance(ExecutionGrantAuthority.Lifetime);
        Assert.NotNull(authority.Issue(Request("knowledge", "lookup", "knowledge:read"), SecurityEventId.New(), "corr"));
        Assert.Equal(1, authority.OutstandingCount);
    }

    [Fact]
    public void Constructor_TwoExecutorsForOneAction_IsAnError_NotAChoice()
    {
        Assert.Throws<InvalidOperationException>(() => new ExecutionGrantAuthority(Authorizer, _approvals, [_knowledge, new CountingExecutor("knowledge", "lookup")], _clock));
    }

    [Fact]
    public void TheSigningKey_IsNotExposed()
    {
        // No member other than the private key field holds key bytes, and nothing public or internal returns any.
        var members = typeof(ExecutionGrantAuthority).GetMembers(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly);
        Assert.DoesNotContain(members.OfType<PropertyInfo>(), property => property.PropertyType == typeof(byte[]));
        Assert.DoesNotContain(members.OfType<MethodInfo>().Where(method => !method.IsPrivate), method => method.ReturnType == typeof(byte[]));
        var keyField = Assert.Single(members.OfType<FieldInfo>(), field => field.FieldType == typeof(byte[]));
        Assert.True(keyField.IsPrivate && keyField.IsInitOnly);
    }

    [Fact]
    public async Task NullArguments_Throw()
    {
        var authority = Authority();
        var (grant, call) = Issue(authority);

        Assert.Throws<ArgumentNullException>(() => authority.Issue(null!, SecurityEventId.New(), "corr"));
        // The authority's own guard, not the boundary's: an authorizer that does not check would fail differently.
        Assert.Throws<ArgumentNullException>(() => new ExecutionGrantAuthority(new AlwaysBlock(), _approvals, [], _clock).Issue(null!, SecurityEventId.New(), "corr"));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await authority.ExecuteAsync(null!, call, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await authority.ExecuteAsync(grant, null!, CancellationToken.None));
        Assert.Throws<ArgumentNullException>(() => new ExecutionGrantAuthority(null!, _approvals, [], _clock));
        Assert.Throws<ArgumentNullException>(() => new ExecutionGrantAuthority(Authorizer, null!, [], _clock));
        Assert.Throws<ArgumentNullException>(() => new ExecutionGrantAuthority(Authorizer, _approvals, null!, _clock));
        Assert.Throws<ArgumentNullException>(() => new ExecutionGrantAuthority(Authorizer, _approvals, [], null!));
    }

    // ── Milestone 13: a Review is granted only for the approval this very request used ────────────────────────────────

    [Fact]
    public void Issue_AReview_WithTheApprovalThisRequestUsed_GetsAGrant()
    {
        var authority = Authority();
        var request = Request("email", "send", "email:send");
        var requestEvent = SecurityEventId.New();
        var approval = Used(request, requestEvent);

        var grant = authority.Issue(request, requestEvent, "corr", approval.Id);

        Assert.NotNull(grant);
        Assert.Equal(new ExecutionScope(requestEvent, "corr", new AgentId("gateway-agent"), new ToolId("email"), new ActionName("send"), new Capability("email:send")), grant.Scope);
    }

    [Fact]
    public void Issue_AnInputHeldForReview_WithTheApprovalThisRequestUsed_GetsAGrant()
    {
        var request = Request("knowledge", "lookup", "knowledge:read", SecurityDecision.Review);
        var requestEvent = SecurityEventId.New();

        Assert.NotNull(Authority().Issue(request, requestEvent, "corr", Used(request, requestEvent).Id));
    }

    [Fact]
    public void Issue_AReview_WithoutAnApprovalItCanVerify_GetsNoGrant()
    {
        var authority = Authority();
        var request = Request("email", "send", "email:send");
        var requestEvent = SecurityEventId.New();
        var approved = Approved(request);
        var usedByAnotherRequest = Used(request, SecurityEventId.New());

        Assert.Null(authority.Issue(request, requestEvent, "corr"));
        Assert.Null(authority.Issue(request, requestEvent, "corr", Guid.NewGuid()));
        Assert.Null(authority.Issue(request, requestEvent, "corr", approved.Id));
        Assert.Null(authority.Issue(request, requestEvent, "corr", usedByAnotherRequest.Id));
        Assert.Equal(0, authority.OutstandingCount);
    }

    [Theory]
    [InlineData("agent")]
    [InlineData("client")]
    [InlineData("tool")]
    [InlineData("action")]
    [InlineData("capability")]
    public void Issue_AnApprovalOfAnotherCall_NeverGrantsThisOne(string differs)
    {
        // The approval was used by this request's event, but binds another agent's or another action's call.
        var request = Request("email", "send", "email:send");
        var requestEvent = SecurityEventId.New();
        var other = differs switch
        {
            "agent" => new ToolApprovalBinding(new AgentId("other-agent"), Runtime, new ToolId("email"), new ActionName("send"), new Capability("email:send"), Digest, null),
            "client" => new ToolApprovalBinding(new AgentId("gateway-agent"), "other-runtime", new ToolId("email"), new ActionName("send"), new Capability("email:send"), Digest, null),
            "tool" => new ToolApprovalBinding(new AgentId("gateway-agent"), Runtime, new ToolId("data"), new ActionName("send"), new Capability("email:send"), Digest, null),
            "action" => new ToolApprovalBinding(new AgentId("gateway-agent"), Runtime, new ToolId("email"), new ActionName("read"), new Capability("email:send"), Digest, null),
            _ => new ToolApprovalBinding(new AgentId("gateway-agent"), Runtime, new ToolId("email"), new ActionName("send"), new Capability("email:read"), Digest, null),
        };
        var approval = Store(ToolApproval.Request(SecurityEventId.New(), "corr", other, HeldVerdict, null, _clock.GetUtcNow(), TimeSpan.FromMinutes(10))
            .Approve(_clock.GetUtcNow(), "approver")
            .Use(other, _clock.GetUtcNow(), requestEvent));

        Assert.Null(Authority().Issue(request, requestEvent, "corr", approval.Id));
    }

    [Theory]
    [InlineData("payment", "execute", "payment:execute", null)]
    [InlineData("knowledge", "lookup", "knowledge:read", SecurityDecision.Block)]
    [InlineData("shell", "exec", "shell:exec", null)]
    public void Issue_ABlock_IsNeverGranted_EvenWithAUsedApproval(string tool, string action, string capability, SecurityDecision? input)
    {
        var request = Request(tool, action, capability, input);
        var requestEvent = SecurityEventId.New();

        Assert.Null(Authority().Issue(request, requestEvent, "corr", Used(request, requestEvent).Id));
    }

    private static readonly string Digest = new('e', 64);

    private static readonly AgentActionAuthorization HeldVerdict = new(
        AgentActionReason.HumanApprovalRequired,
        Domain.Risk.RiskLevel.High,
        new RecognisedAgentAction(new AgentId("gateway-agent"), new ToolId("email"), new ActionName("send"), new Capability("email:send")));

    private ToolApproval Approved(AgentActionRequest request)
    {
        var binding = new ToolApprovalBinding(request.Agent, request.Caller, request.Tool, request.Action, request.Capability, Digest, null);
        return Store(ToolApproval.Request(SecurityEventId.New(), "corr", binding, HeldVerdict, request.InputDecision, _clock.GetUtcNow(), TimeSpan.FromMinutes(10))
            .Approve(_clock.GetUtcNow(), "approver"));
    }

    private ToolApproval Used(AgentActionRequest request, SecurityEventId by)
    {
        var approved = Approved(request);
        return Store(approved.Use(approved.Binding, _clock.GetUtcNow(), by));
    }

    private ToolApproval Store(ToolApproval approval)
    {
        _approvals.Put(approval);
        return approval;
    }

    private ExecutionGrantAuthority Authority() => new(Authorizer, _approvals, [_knowledge, _write], _clock);

    private static (ExecutionGrant Grant, ToolCall Call) Issue(ExecutionGrantAuthority authority)
    {
        var grant = authority.Issue(Request("knowledge", "lookup", "knowledge:read"), SecurityEventId.New(), "corr-grant")
            ?? throw new InvalidOperationException("The test request should be allowed.");
        return (grant, new ToolCall(grant.Scope, new KnowledgeLookupArguments("dependency injection")));
    }

    private static AgentActionRequest Request(string tool, string action, string capability, SecurityDecision? input = null, string caller = Runtime) =>
        new(caller, new AgentId("gateway-agent"), new ToolId(tool), new ActionName(action), new Capability(capability), input);

    private static ExecutionGrant Rescope(ExecutionGrant grant, ExecutionScope scope) =>
        new(grant.ExecutionId, scope, grant.IssuedAt, grant.ExpiresAt, grant.Signature);

    private static ExecutionScope With(
        ExecutionScope scope,
        AgentId? agent = null,
        ToolId? tool = null,
        ActionName? action = null,
        Capability? capability = null,
        SecurityEventId? securityEventId = null,
        string? correlationId = null) =>
        new(securityEventId ?? scope.SecurityEventId, correlationId ?? scope.CorrelationId, agent ?? scope.Agent, tool ?? scope.Tool, action ?? scope.Action, capability ?? scope.Capability);

    private static string Flip(string signature) => (signature[0] == '0' ? "1" : "0") + signature[1..];

    private static Capability[] Capabilities(params string[] values) => [.. values.Select(value => new Capability(value))];

    /// <summary>Counts calls and records the arguments it was given.</summary>
    private sealed class CountingExecutor(string tool, string action) : IToolExecutor
    {
        public static readonly ToolOutput Output = new(found: true, "counted");

        private int _calls;

        public ToolId Tool { get; } = new(tool);

        public ActionName Action { get; } = new(action);

        public Exception? Failure { get; init; }

        public int Calls => _calls;

        public ConcurrentQueue<ToolArguments> Received { get; } = new();

        public void Reset() => Interlocked.Exchange(ref _calls, 0);

        public ValueTask<ToolOutput> ExecuteAsync(ToolArguments arguments, CancellationToken cancellationToken)
        {
            Interlocked.Increment(ref _calls);
            Received.Enqueue(arguments);
            return Failure is { } failure ? ValueTask.FromException<ToolOutput>(failure) : ValueTask.FromResult(Output);
        }
    }

    private sealed class AlwaysBlock : IAgentActionAuthorizer
    {
        public AgentActionAuthorization Authorize(AgentActionRequest request) =>
            new(AgentActionReason.CapabilityNotGranted, Domain.Risk.RiskLevel.Low, new RecognisedAgentAction(request.Agent, request.Tool, request.Action, request.Capability));
    }
}
