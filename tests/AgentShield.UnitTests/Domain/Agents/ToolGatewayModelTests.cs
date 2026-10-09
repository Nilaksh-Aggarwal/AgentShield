using AgentShield.Application.Abstractions.Agents;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Domain.Policy;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.UnitTests.Domain.Agents;

/// <summary>
/// The tool gateway's domain model: each outcome has one decision and only an invoked tool is an Allow; arguments and
/// outputs cannot exist outside their schema; a grant is bound to a complete scope; an agent's gateway identity is one of its
/// bound callers.
/// </summary>
public sealed class ToolGatewayModelTests
{
    [Theory]
    [InlineData(ToolExecutionOutcome.Executed, SecurityDecision.Allow, true)]
    [InlineData(ToolExecutionOutcome.ExecutionFailed, SecurityDecision.Allow, true)]
    [InlineData(ToolExecutionOutcome.HeldForReview, SecurityDecision.Review, false)]
    [InlineData(ToolExecutionOutcome.Denied, SecurityDecision.Block, false)]
    [InlineData(ToolExecutionOutcome.ArgumentsRejected, SecurityDecision.Block, false)]
    [InlineData(ToolExecutionOutcome.ToolUnavailable, SecurityDecision.Block, false)]
    [InlineData(ToolExecutionOutcome.ExecutionAuthorizationRejected, SecurityDecision.Block, false)]
    [InlineData(ToolExecutionOutcome.InputContextRejected, SecurityDecision.Block, false)]
    [InlineData(ToolExecutionOutcome.ApprovalRejected, SecurityDecision.Block, false)]
    public void DecisionFor_EachOutcome_HasExactlyOneDecision_AndOnlyAnInvokedToolIsAnAllow(ToolExecutionOutcome outcome, SecurityDecision decision, bool invoked)
    {
        Assert.Equal(decision, ToolExecutionOutcomes.DecisionFor(outcome));
        Assert.Equal(invoked, ToolExecutionOutcomes.ToolWasInvoked(outcome));
    }

    [Fact]
    public void DecisionFor_CoversEveryOutcome_AndAnUndefinedOneThrows()
    {
        Assert.Equal(9, Enum.GetValues<ToolExecutionOutcome>().Length);
        Assert.All(Enum.GetValues<ToolExecutionOutcome>(), outcome => Assert.True(Enum.IsDefined(ToolExecutionOutcomes.DecisionFor(outcome))));
        Assert.Throws<ArgumentOutOfRangeException>(() => ToolExecutionOutcomes.DecisionFor((ToolExecutionOutcome)99));
        Assert.Throws<ArgumentOutOfRangeException>(() => ToolExecutionOutcomes.DecisionFor(0));
    }

    [Theory]
    [InlineData("dependency injection")]
    [InlineData("x")]
    [InlineData("  padded  ")]
    [InlineData("Ünïcödé query ✓")]
    [InlineData("emoji 😀 pair")]
    public void KnowledgeLookupArguments_AValidQuery_IsKeptExactlyAsSent(string query)
    {
        Assert.Null(KnowledgeLookupArguments.Validate(query));
        Assert.Equal(query, new KnowledgeLookupArguments(query).Query);
    }

    [Fact]
    public void KnowledgeLookupArguments_LengthIsBoundedAt200Characters()
    {
        Assert.Equal(200, KnowledgeLookupArguments.MaxQueryLength);
        Assert.Null(KnowledgeLookupArguments.Validate(new string('a', 200)));
        Assert.Equal(ToolArgumentViolation.TooLong, KnowledgeLookupArguments.Validate(new string('a', 201)));
        Assert.Throws<ArgumentException>(() => new KnowledgeLookupArguments(new string('a', 201)));
    }

    [Theory]
    [InlineData("", ToolArgumentViolation.Empty)]
    [InlineData(" ", ToolArgumentViolation.Empty)]
    [InlineData("   ", ToolArgumentViolation.Empty)]
    [InlineData("a\nb", ToolArgumentViolation.InvalidText)]
    [InlineData("a\rb", ToolArgumentViolation.InvalidText)]
    [InlineData("a\tb", ToolArgumentViolation.InvalidText)]
    [InlineData("a\0b", ToolArgumentViolation.InvalidText)]
    [InlineData("a\u007fb", ToolArgumentViolation.InvalidText)]
    [InlineData("a\u0085b", ToolArgumentViolation.InvalidText)]
    [InlineData("a\u001bb", ToolArgumentViolation.InvalidText)]
    public void KnowledgeLookupArguments_EmptyOrControlCharacters_AreRejected(string query, ToolArgumentViolation violation)
    {
        Assert.Equal(violation, KnowledgeLookupArguments.Validate(query));
        Assert.Throws<ArgumentException>(() => new KnowledgeLookupArguments(query));
    }

    [Fact]
    public void KnowledgeLookupArguments_IllFormedUtf16_IsRejected()
    {
        // Built in code: attribute arguments are stored as UTF-8, which would turn a lone surrogate into U+FFFD.
        const char High = (char)0xD800;
        const char Low = (char)0xDC00;
        string[] queries = ["a" + High, High + "a", "a" + Low + "b", string.Concat(Low, High), string.Concat(High, High), "ok" + Low];

        Assert.All(queries, query => Assert.Equal(ToolArgumentViolation.InvalidText, KnowledgeLookupArguments.Validate(query)));
        Assert.Null(KnowledgeLookupArguments.Validate(string.Concat(High, Low)));
    }

    [Fact]
    public void KnowledgeLookupArguments_RejectionMessages_NeverQuoteTheValue()
    {
        const string Marker = "zq7gwquery";
        var exception = Assert.Throws<ArgumentException>(() => new KnowledgeLookupArguments(Marker + "\n" + Marker));

        Assert.DoesNotContain(Marker, exception.Message, StringComparison.Ordinal);
        Assert.Throws<ArgumentNullException>(() => new KnowledgeLookupArguments(null!));
        Assert.Throws<ArgumentNullException>(() => KnowledgeLookupArguments.Validate(null!));
    }

    [Fact]
    public void ToolOutput_IsBounded_AndNothingFoundCarriesNoText()
    {
        Assert.Equal(2_000, ToolOutput.MaxTextLength);
        Assert.Equal("x", new ToolOutput(found: true, "x").Text);
        Assert.Equal(2_000, new ToolOutput(found: true, new string('a', 2_000)).Text!.Length);
        Assert.Throws<ArgumentOutOfRangeException>(() => new ToolOutput(found: true, new string('a', 2_001)));
        Assert.Throws<ArgumentOutOfRangeException>(() => new ToolOutput(found: true, string.Empty));
        Assert.Throws<ArgumentException>(() => new ToolOutput(found: false, "text"));
        Assert.Equal((false, (string?)null), (ToolOutput.NotFound.Found, ToolOutput.NotFound.Text));
        Assert.True(new ToolOutput(found: true, text: null).Found);
    }

    [Fact]
    public void ExecutionScope_RequiresEveryPart()
    {
        var id = SecurityEventId.New();
        Assert.Throws<ArgumentException>(() => Scope(default, "corr"));
        Assert.Throws<ArgumentException>(() => Scope(id, " "));
        Assert.Throws<ArgumentException>(() => Scope(id, string.Empty));
        Assert.Throws<ArgumentNullException>(() => new ExecutionScope(id, "corr", null!, new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read")));
        Assert.Throws<ArgumentNullException>(() => new ExecutionScope(id, "corr", new AgentId("a"), null!, new ActionName("lookup"), new Capability("knowledge:read")));
        Assert.Throws<ArgumentNullException>(() => new ExecutionScope(id, "corr", new AgentId("a"), new ToolId("knowledge"), null!, new Capability("knowledge:read")));
        Assert.Throws<ArgumentNullException>(() => new ExecutionScope(id, "corr", new AgentId("a"), new ToolId("knowledge"), new ActionName("lookup"), null!));
    }

    [Fact]
    public void ExecutionScope_ComparesEveryPart()
    {
        var id = SecurityEventId.New();
        Assert.Equal(Scope(id, "corr"), Scope(id, "corr"));
        Assert.NotEqual(Scope(id, "corr"), Scope(id, "corr-2"));
        Assert.NotEqual(Scope(id, "corr"), Scope(SecurityEventId.New(), "corr"));
    }

    [Fact]
    public void ExecutionGrant_RequiresAnId_ALaterExpiry_AndASignature()
    {
        var scope = Scope(SecurityEventId.New(), "corr");
        var now = DateTimeOffset.UnixEpoch.AddYears(56);

        var grant = new ExecutionGrant(Guid.CreateVersion7(), scope, now, now.AddSeconds(30), "ab");
        Assert.Equal((scope, now, now.AddSeconds(30), "ab"), (grant.Scope, grant.IssuedAt, grant.ExpiresAt, grant.Signature));

        Assert.Throws<ArgumentException>(() => new ExecutionGrant(Guid.Empty, scope, now, now.AddSeconds(30), "ab"));
        Assert.Throws<ArgumentException>(() => new ExecutionGrant(Guid.CreateVersion7(), scope, now, now, "ab"));
        Assert.Throws<ArgumentException>(() => new ExecutionGrant(Guid.CreateVersion7(), scope, now, now.AddTicks(-1), "ab"));
        Assert.Throws<ArgumentException>(() => new ExecutionGrant(Guid.CreateVersion7(), scope, now, now.AddSeconds(30), " "));
        Assert.Throws<ArgumentNullException>(() => new ExecutionGrant(Guid.CreateVersion7(), null!, now, now.AddSeconds(30), "ab"));
    }

    [Fact]
    public void ToString_NeverPrintsAGrantsSignature_OrTheQuery()
    {
        var now = DateTimeOffset.UnixEpoch.AddYears(56);
        var grant = new ExecutionGrant(Guid.CreateVersion7(), Scope(SecurityEventId.New(), "corr"), now, now.AddSeconds(30), "zq7signaturehex");
        var arguments = new KnowledgeLookupArguments("zq7 untrusted query");

        Assert.DoesNotContain("zq7", grant.ToString(), StringComparison.Ordinal);
        Assert.Contains(grant.ExecutionId.ToString(), grant.ToString(), StringComparison.Ordinal);
        Assert.Equal("KnowledgeLookupArguments { Query = (19 characters) }", arguments.ToString());
        Assert.DoesNotContain("zq7", ToolArgumentCheck.Accept(arguments).ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public void ExecutionGrant_HasNoDecisionField_SoThereIsNothingToTurnIntoAnAllow()
    {
        string[] names = [.. typeof(ExecutionGrant).GetProperties().Select(property => property.Name).Order(StringComparer.Ordinal)];

        Assert.Equal(["ExecutionId", "ExpiresAt", "IssuedAt", "Scope", "Signature"], names);
        Assert.Equal(["Action", "Agent", "Capability", "CorrelationId", "SecurityEventId", "Tool"],
            typeof(ExecutionScope).GetProperties().Select(property => property.Name).Order(StringComparer.Ordinal).ToArray());
    }

    [Fact]
    public void AgentProfile_GatewayClient_MustBeOneOfItsBoundCallers()
    {
        var profile = new AgentProfile(new AgentId("support-agent"), [], ["runtime-a", "runtime-b"], gatewayClient: "runtime-b");
        Assert.Equal("runtime-b", profile.GatewayClient);
        Assert.Null(new AgentProfile(new AgentId("support-agent"), [], ["runtime-a"]).GatewayClient);

        Assert.Throws<ArgumentException>(() => new AgentProfile(new AgentId("support-agent"), [], ["runtime-a"], gatewayClient: "runtime-b"));
        Assert.Throws<ArgumentException>(() => new AgentProfile(new AgentId("support-agent"), [], ["runtime-a"], gatewayClient: "Runtime-A"));
        Assert.Throws<ArgumentException>(() => new AgentProfile(new AgentId("support-agent"), [], [], gatewayClient: "runtime-a"));
    }

    private static ExecutionScope Scope(SecurityEventId id, string correlationId) =>
        new(id, correlationId, new AgentId("support-agent"), new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read"));
}
