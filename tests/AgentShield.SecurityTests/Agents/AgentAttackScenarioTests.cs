using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using static AgentShield.SecurityTests.Agents.AgentTestData;

namespace AgentShield.SecurityTests.Agents;

/// <summary>
/// Representative agent attacks against the authorization boundary (docs/security/agent-action-authorization.md, section
/// "Attack scenarios"), each with the production reference catalogue. Nothing here executes a tool: the boundary only decides.
/// </summary>
public sealed class AgentAttackScenarioTests
{
    [Theory]
    [InlineData("research-agent", "email", "send", "email:send")]
    [InlineData("research-agent", "browser", "submit", "browser:submit")]
    [InlineData("idle-agent", "data", "read", "data:read")]
    public void Scenario1_UnauthorizedTool_AnAgentWithNoCapabilityForTheTool_IsBlocked(string agent, string tool, string action, string capability)
    {
        var authorization = Authorize(agent, tool, action, capability);

        Assert.Equal((SecurityDecision.Block, AgentActionReason.CapabilityNotGranted), (authorization.Decision, authorization.Reason));
    }

    [Fact]
    public void Scenario2_WrongCapability_AnAgentWithDataReadRequestingDataWrite_IsBlocked()
    {
        // Asking honestly for the capability it lacks, or presenting the one it holds for the write: both blocked.
        var honest = Authorize("research-agent", "data", "write", "data:write");
        var borrowed = Authorize("research-agent", "data", "write", "data:read");

        Assert.Equal((SecurityDecision.Block, AgentActionReason.CapabilityNotGranted, RiskLevel.Medium), (honest.Decision, honest.Reason, honest.Risk));
        Assert.Equal((SecurityDecision.Block, AgentActionReason.CapabilityMismatch), (borrowed.Decision, borrowed.Reason));
    }

    [Theory]
    [InlineData("support-agent", "email", "send", "email:send")]
    [InlineData("research-agent", "browser", "navigate", "browser:navigate")]
    [InlineData("operations-agent", "customer", "update", "customer:write")]
    public void Scenario3_HighImpactAction_WithTheCapability_IsHeldForHumanReview(string agent, string tool, string action, string capability)
    {
        var authorization = Authorize(agent, tool, action, capability);

        Assert.Equal((SecurityDecision.Review, AgentActionReason.HumanApprovalRequired, RiskLevel.High), (authorization.Decision, authorization.Reason, authorization.Risk));
    }

    [Theory]
    [InlineData("research-agent", "data", "read", RiskLevel.Low)]
    [InlineData("support-agent", "data", "describe", RiskLevel.Low)]
    [InlineData("support-agent", "email", "read", RiskLevel.Low)]
    public void Scenario4_SafeRead_WithTheCorrectCapability_IsAllowed(string agent, string tool, string action, RiskLevel risk)
    {
        var capability = tool == "data" ? "data:read" : $"{tool}:{action}";

        var authorization = Authorize(agent, tool, action, capability);

        Assert.Equal((SecurityDecision.Allow, AgentActionReason.Permitted, risk), (authorization.Decision, authorization.Reason, authorization.Risk));
    }

    [Theory]
    [InlineData("support-agent", "identity", "grant", "identity:grant")]
    [InlineData("support-agent", "payment", "execute", "payment:execute")]
    [InlineData("support-agent", "secrets", "read", "secrets:read")]
    [InlineData("research-agent", "data", "delete", "data:delete")]
    [InlineData("operations-agent", "email", "send", "email:send")]
    public void Scenario5_PrivilegeEscalation_RequestingACapabilityTheAgentDoesNotPossess_IsBlocked(string agent, string tool, string action, string capability)
    {
        var authorization = Authorize(agent, tool, action, capability);

        Assert.Equal((SecurityDecision.Block, AgentActionReason.CapabilityNotGranted), (authorization.Decision, authorization.Reason));
    }

    [Fact]
    public void Scenario5_PrivilegeEscalation_BorrowingAnotherAgentsIdentity_IsBlocked()
    {
        // runtime-a runs the support agent; naming the finance agent does not lend it the finance agent's grants.
        var authorization = Authorize("finance-agent", "data", "read", "data:read", caller: RuntimeA);

        Assert.Equal((SecurityDecision.Block, AgentActionReason.CallerNotBoundToAgent), (authorization.Decision, authorization.Reason));
    }

    [Theory]
    [InlineData("support-agent", "shell", "exec", "shell:exec", AgentActionReason.UnknownTool)]
    [InlineData("support-agent", "mcp", "call", "mcp:call", AgentActionReason.UnknownTool)]
    [InlineData("support-agent", "email", "delete", "email:delete", AgentActionReason.UnknownAction)]
    [InlineData("support-agent", "email", "forward", "email:send", AgentActionReason.UnknownAction)]
    [InlineData("ghost-agent", "data", "read", "data:read", AgentActionReason.UnknownAgent)]
    [InlineData("ghost-agent", "shell", "exec", "shell:exec", AgentActionReason.UnknownAgent)]
    public void Scenario6_UnknownToolActionOrAgent_IsBlocked_NeverSilentlyAllowed(string agent, string tool, string action, string capability, AgentActionReason reason)
    {
        foreach (var input in new SecurityDecision?[] { null, SecurityDecision.Allow })
        {
            var authorization = Authorize(agent, tool, action, capability, input);

            Assert.Equal((SecurityDecision.Block, reason), (authorization.Decision, authorization.Reason));
        }
    }

    [Theory]
    [InlineData("support-agent", "payment", "execute", "payment:execute")] // Block: not granted
    [InlineData("finance-agent", "payment", "execute", "payment:execute")] // Block: critical, even though granted
    [InlineData("support-agent", "shell", "exec", "shell:exec")] // Block: unknown tool
    [InlineData("support-agent", "email", "send", "email:send")] // Review: high impact
    public void Scenario7_PolicyIntegrity_NothingTheAgentProvides_TurnsBlockOrReviewIntoAllow(string agent, string tool, string action, string capability)
    {
        var caller = agent == "finance-agent" ? RuntimeB : RuntimeA;
        var honest = Authorize(agent, tool, action, capability, caller: caller);
        Assert.NotEqual(SecurityDecision.Allow, honest.Decision);

        // Every capability it could claim (held ones, the catalogue's, made-up ones) and every input decision it could report.
        string[] claims = [.. Catalog.Capabilities.Select(claim => claim.Value), "admin:all", "email:send-all", capability];
        foreach (var claim in claims)
        {
            foreach (var input in new SecurityDecision?[] { null, SecurityDecision.Allow, SecurityDecision.Review, SecurityDecision.Block })
            {
                var attempt = Authorize(agent, tool, action, claim, input, caller);

                Assert.NotEqual(SecurityDecision.Allow, attempt.Decision);
                Assert.True(Rank(attempt.Decision) >= Rank(honest.Decision));
            }
        }
    }

    [Fact]
    public void Scenario7_PolicyIntegrity_ACriticalActionStaysBlocked_ForTheAgentThatHoldsItsCapability()
    {
        var authorization = Authorize("finance-agent", "payment", "execute", "payment:execute", SecurityDecision.Allow, RuntimeB);

        Assert.Equal((SecurityDecision.Block, AgentActionReason.CriticalActionDenied, RiskLevel.Critical), (authorization.Decision, authorization.Reason, authorization.Risk));
    }

    [Fact]
    public void Scenario7_PolicyIntegrity_AnExistingBlockOrReviewOnTheInput_IsNeverLiftedByASafeAction()
    {
        // Invariants 49-50: agent authorization cannot convert an existing Block or Review into Allow.
        var afterBlock = Authorize("research-agent", "data", "read", "data:read", SecurityDecision.Block);
        var afterReview = Authorize("research-agent", "data", "read", "data:read", SecurityDecision.Review);
        var afterAllow = Authorize("research-agent", "data", "read", "data:read", SecurityDecision.Allow);

        Assert.Equal((SecurityDecision.Block, AgentActionReason.InputBlocked), (afterBlock.Decision, afterBlock.Reason));
        Assert.Equal((SecurityDecision.Review, AgentActionReason.InputHeldForReview), (afterReview.Decision, afterReview.Reason));
        Assert.Equal(SecurityDecision.Allow, afterAllow.Decision);
    }
}
