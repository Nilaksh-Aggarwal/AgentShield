using AgentShield.Application.Abstractions.Agents;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.UnitTests.Application.Agents;

/// <summary>
/// The gateway's port result types: an argument check is either validated arguments or a known violation, an execution
/// attempt either an output or a known rejection — never both, never neither, never an undefined code.
/// </summary>
public sealed class ToolGatewayResultTypesTests
{
    [Fact]
    public void ToolArgumentCheck_AcceptedCarriesTheArguments_RejectedCarriesTheViolation()
    {
        var arguments = new KnowledgeLookupArguments("di");

        var accepted = ToolArgumentCheck.Accept(arguments);
        var rejected = ToolArgumentCheck.Reject(ToolArgumentViolation.TooLong);

        Assert.Equal((true, arguments, (ToolArgumentViolation?)null), (accepted.IsAccepted, accepted.Arguments, accepted.Violation));
        Assert.Equal((false, (ToolArguments?)null, (ToolArgumentViolation?)ToolArgumentViolation.TooLong), (rejected.IsAccepted, rejected.Arguments, rejected.Violation));
    }

    [Fact]
    public void ToolArgumentCheck_NoArgumentsOrAnUndefinedViolation_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => ToolArgumentCheck.Accept(null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => ToolArgumentCheck.Reject((ToolArgumentViolation)99));
        Assert.Throws<ArgumentOutOfRangeException>(() => ToolArgumentCheck.Reject(0));
    }

    [Fact]
    public void ToolExecutionAttempt_RanCarriesTheOutput_RefusedCarriesTheRejection()
    {
        var output = new ToolOutput(found: true, "text");

        var ran = ToolExecutionAttempt.Ran(output);
        var refused = ToolExecutionAttempt.Refused(ExecutionGrantRejection.Expired);

        Assert.Equal((true, output, (ExecutionGrantRejection?)null), (ran.Executed, ran.Output, ran.Rejection));
        Assert.Equal((false, (ToolOutput?)null, (ExecutionGrantRejection?)ExecutionGrantRejection.Expired), (refused.Executed, refused.Output, refused.Rejection));
    }

    [Fact]
    public void ToolExecutionAttempt_NoOutputOrAnUndefinedRejection_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => ToolExecutionAttempt.Ran(null!));
        Assert.Throws<ArgumentOutOfRangeException>(() => ToolExecutionAttempt.Refused((ExecutionGrantRejection)99));
        Assert.Throws<ArgumentOutOfRangeException>(() => ToolExecutionAttempt.Refused(0));
    }

    [Fact]
    public void ToolCall_RequiresAScopeAndArguments()
    {
        var scope = new ExecutionScope(SecurityEventId.New(), "corr", new AgentId("support-agent"), new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read"));

        Assert.Throws<ArgumentNullException>(() => new ToolCall(null!, new KnowledgeLookupArguments("di")));
        Assert.Throws<ArgumentNullException>(() => new ToolCall(scope, null!));
        Assert.Same(scope, new ToolCall(scope, new KnowledgeLookupArguments("di")).Scope);
    }
}
