using System.Net;
using System.Text.Json;
using AgentShield.ApiTests.Infrastructure;

namespace AgentShield.ApiTests.Agents;

/// <summary>
/// The gateway with more tools than production has: harmless test executors for a Medium (data.write), two High
/// (email.send, browser.navigate) and a Critical (payment.execute) action, all held by the agent. The gateway consumes the
/// existing M10 policy unchanged: Low and Medium run, High is held for review, Critical is blocked — even though an
/// executor exists and the agent holds the capability — and a stricter input decision stops even a Low or Medium action.
/// </summary>
public sealed class ToolGatewayRiskModelTests(ToolGatewayRiskModelTests.WithTestTools factory) : IClassFixture<ToolGatewayRiskModelTests.WithTestTools>
{
    [Theory]
    [InlineData("knowledge", "lookup", "knowledge:read", "Low", "Allow", "Executed", true)]
    [InlineData("data", "write", "data:write", "Medium", "Allow", "Executed", true)]
    [InlineData("email", "send", "email:send", "High", "Review", "HeldForReview", false)]
    [InlineData("browser", "navigate", "browser:navigate", "High", "Review", "HeldForReview", false)]
    [InlineData("payment", "execute", "payment:execute", "Critical", "Block", "Denied", false)]
    public async Task Execute_EachRiskLevel_GetsThePolicysDecision_AndOnlyAnAllowRuns(string tool, string action, string capability, string risk, string decision, string outcome, bool runs)
    {
        var before = factory.Probe.Count;
        var arguments = tool == "knowledge" ? """{"query":"least privilege"}""" : """{"note":"harmless"}""";

        var data = await OkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Body(tool, action, capability, arguments)));

        Assert.Equal((risk, decision, outcome, runs), (
            data.GetProperty("riskLevel").GetString(),
            data.GetProperty("decision").GetString(),
            data.GetProperty("outcome").GetString(),
            data.GetProperty("executed").GetBoolean()));
        Assert.Equal(before + (runs ? 1 : 0), factory.Probe.Count);
        if (runs)
        {
            Assert.Equal((tool, action), (factory.Probe.Invocations[^1].Tool, factory.Probe.Invocations[^1].Action));
        }
    }

    [Fact]
    public async Task Execute_EveryTestedActionAndInputDecision_RunsTheTool_ExactlyWhenTheDecisionIsAllow()
    {
        (string Tool, string Action, string Capability)[] actions =
        [
            ("knowledge", "lookup", "knowledge:read"),
            ("data", "write", "data:write"),
            ("email", "send", "email:send"),
            ("browser", "navigate", "browser:navigate"),
            ("payment", "execute", "payment:execute"),
        ];
        string?[] inputs = [null, "Allow", "Review", "Block"];

        var combinations = 0;
        foreach (var (tool, action, capability) in actions)
        {
            foreach (var input in inputs)
            {
                var before = factory.Probe.Count;
                var arguments = tool == "knowledge" ? """{"query":"fail closed"}""" : "{}";

                var data = await OkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Body(tool, action, capability, arguments, input)));

                var decision = data.GetProperty("decision").GetString();
                var ran = factory.Probe.Count - before;
                Assert.True((decision == "Allow" ? 1 : 0) == ran, $"{tool}.{action} with input {input ?? "(none)"}: {decision}, ran {ran}");
                Assert.Equal(decision == "Allow", data.GetProperty("executed").GetBoolean());
                Assert.False(input is "Review" or "Block" && decision == "Allow", $"{tool}.{action}: input {input} was lifted to Allow");
                combinations++;
            }
        }

        Assert.Equal(20, combinations);
    }

    [Fact]
    public async Task Execute_AMediumActionWithAnInputUnderReview_IsHeldForReview_AndDoesNotRun()
    {
        var before = factory.Probe.Count;

        var data = await OkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Body("data", "write", "data:write", "{}", "Review")));

        Assert.Equal(("Review", "InputHeldForReview", false), (data.GetProperty("decision").GetString(), data.GetProperty("authorizationReason").GetString(), data.GetProperty("executed").GetBoolean()));
        Assert.Equal(before, factory.Probe.Count);
    }

    private static async Task<JsonElement> OkAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, body);
        using var document = JsonDocument.Parse(body);
        return document.RootElement.GetProperty("data").Clone();
    }

    /// <summary>The gateway agents plus the test tools.</summary>
    public sealed class WithTestTools() : GatewayApiFactory(withTestTools: true);
}
