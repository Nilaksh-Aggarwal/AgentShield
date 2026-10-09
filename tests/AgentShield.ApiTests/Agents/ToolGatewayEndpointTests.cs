using System.Net;
using System.Text.Json;
using AgentShield.Api.Auth;
using AgentShield.ApiTests.Infrastructure;
using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Activity;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Domain.SecurityEvents;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using static AgentShield.ApiTests.Infrastructure.GatewayApiFactory;

namespace AgentShield.ApiTests.Agents;

/// <summary>
/// The tool gateway's security matrix over HTTP (<c>POST /api/v1/agent/tools/execute</c>), through the real pipeline with a
/// probe on every tool executor: the tool runs exactly once on Allow and never otherwise — not on Review or Block, not for
/// an unknown tool or action, a missing capability, bad arguments, another agent's identity or a field asserting authority.
/// </summary>
public sealed class ToolGatewayEndpointTests(GatewayApiFactory factory) : IClassFixture<GatewayApiFactory>
{
    private const string ActivityRoute = "/api/v1/activity";

    // ── Allow: the tool runs exactly once ───────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Execute_AnAllowedLookup_RunsTheToolExactlyOnce_AndReturnsItsResult()
    {
        var before = factory.Probe.Count;

        var data = await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Lookup("dependency injection")));

        Assert.Equal(("Allow", true, "Executed"), (data.GetProperty("decision").GetString(), data.GetProperty("executed").GetBoolean(), data.GetProperty("outcome").GetString()));
        Assert.Equal(("Permitted", "Low"), (data.GetProperty("authorizationReason").GetString(), data.GetProperty("riskLevel").GetString()));
        Assert.NotEqual(Guid.Empty, data.GetProperty("executionId").GetGuid());
        Assert.NotEqual(Guid.Empty, data.GetProperty("securityEventId").GetGuid());
        var result = data.GetProperty("result");
        Assert.True(result.GetProperty("found").GetBoolean());
        Assert.StartsWith("Dependency injection:", result.GetProperty("text").GetString(), StringComparison.Ordinal);

        Assert.Equal(before + 1, factory.Probe.Count);
        var invocation = factory.Probe.Invocations[^1];
        Assert.Equal(("knowledge", "lookup"), (invocation.Tool, invocation.Action));
        Assert.Equal(new KnowledgeLookupArguments("dependency injection"), invocation.Arguments);
    }

    [Fact]
    public async Task Execute_ALookupThatFindsNothing_StillRan_AndSaysSo()
    {
        var before = factory.Probe.Count;

        var data = await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Lookup("quantum gravity")));

        Assert.True(data.GetProperty("executed").GetBoolean());
        Assert.False(data.GetProperty("result").GetProperty("found").GetBoolean());
        Assert.Equal(JsonValueKind.Null, data.GetProperty("result").GetProperty("text").ValueKind);
        Assert.Equal(before + 1, factory.Probe.Count);
    }

    [Fact]
    public async Task Execute_EachRequestGetsItsOwnExecution()
    {
        var first = await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Lookup("rate limiting")));
        var second = await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Lookup("rate limiting")));

        Assert.NotEqual(first.GetProperty("executionId").GetGuid(), second.GetProperty("executionId").GetGuid());
        Assert.NotEqual(first.GetProperty("securityEventId").GetGuid(), second.GetProperty("securityEventId").GetGuid());
    }

    // ── Review and Block: the tool never runs ───────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(GatewayKey, "email", "send", "email:send", null, "Review", "HeldForReview", "HumanApprovalRequired", "High")]
    [InlineData(GatewayKey, "browser", "navigate", "browser:navigate", null, "Review", "HeldForReview", "HumanApprovalRequired", "High")]
    [InlineData(GatewayKey, "knowledge", "lookup", "knowledge:read", "Review", "Review", "HeldForReview", "InputHeldForReview", "Low")]
    [InlineData(GatewayKey, "knowledge", "lookup", "knowledge:read", "Block", "Block", "Denied", "InputBlocked", "Low")]
    [InlineData(GatewayKey, "payment", "execute", "payment:execute", null, "Block", "Denied", "CriticalActionDenied", "Critical")]
    [InlineData(GatewayKey, "secrets", "read", "secrets:read", null, "Block", "Denied", "CapabilityNotGranted", "Critical")]
    [InlineData(GatewayKey, "identity", "grant", "identity:grant", null, "Block", "Denied", "CapabilityNotGranted", "Critical")]
    [InlineData(GatewayKey, "data", "delete", "data:delete", null, "Block", "Denied", "CapabilityNotGranted", "Critical")]
    [InlineData(GatewayKey, "shell", "exec", "shell:exec", null, "Block", "Denied", "UnknownTool", "Critical")]
    [InlineData(GatewayKey, "knowledge", "delete", "knowledge:read", null, "Block", "Denied", "UnknownAction", "Critical")]
    [InlineData(GatewayKey, "knowledge", "search", "knowledge:read", null, "Block", "Denied", "UnknownAction", "Critical")]
    [InlineData(GatewayKey, "knowledge", "lookup", "data:read", null, "Block", "Denied", "CapabilityMismatch", "Low")]
    [InlineData(GatewayKey, "knowledge", "lookup", "knowledge:write", null, "Block", "Denied", "CapabilityMismatch", "Low")]
    [InlineData(ReaderKey, "knowledge", "lookup", "knowledge:read", null, "Block", "Denied", "CapabilityNotGranted", "Low")]
    [InlineData(ReaderKey, "knowledge", "lookup", "knowledge:read", "Allow", "Block", "Denied", "CapabilityNotGranted", "Low")]
    public async Task Execute_AnythingTheBoundaryDoesNotAllow_IsReturnedAsDecided_AndTheToolNeverRuns(
        string apiKey, string tool, string action, string capability, string? input, string decision, string outcome, string reason, string risk)
    {
        var before = factory.Probe.Count;

        var data = await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Body(tool, action, capability, inputDecision: input), apiKey));

        Assert.Equal((decision, false, outcome), (data.GetProperty("decision").GetString(), data.GetProperty("executed").GetBoolean(), data.GetProperty("outcome").GetString()));
        Assert.Equal((reason, risk), (data.GetProperty("authorizationReason").GetString(), data.GetProperty("riskLevel").GetString()));
        Assert.Equal(JsonValueKind.Null, data.GetProperty("executionId").ValueKind);
        Assert.Equal(JsonValueKind.Null, data.GetProperty("result").ValueKind);
        Assert.Equal(before, factory.Probe.Count);
    }

    [Fact]
    public async Task Execute_AnInputDecisionOfAllow_ChangesNothing_AndCannotLiftAReview()
    {
        var allowed = await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Body("knowledge", "lookup", "knowledge:read", inputDecision: "Allow")));
        var before = factory.Probe.Count;
        var review = await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Body("email", "send", "email:send", inputDecision: "Allow")));

        Assert.Equal("Executed", allowed.GetProperty("outcome").GetString());
        Assert.Equal(("Review", false), (review.GetProperty("decision").GetString(), review.GetProperty("executed").GetBoolean()));
        Assert.Equal(before, factory.Probe.Count);
    }

    [Theory]
    [InlineData("data", "read", "data:read", "Low")]
    [InlineData("data", "describe", "data:read", "Low")]
    [InlineData("data", "write", "data:write", "Medium")]
    public async Task Execute_AnAllowedActionNoToolHereImplements_IsBlocked_AndNothingRuns(string tool, string action, string capability, string risk)
    {
        var before = factory.Probe.Count;

        var data = await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Body(tool, action, capability, "{}")));

        Assert.Equal(("Block", false, "ToolUnavailable", "Permitted", risk), (
            data.GetProperty("decision").GetString(),
            data.GetProperty("executed").GetBoolean(),
            data.GetProperty("outcome").GetString(),
            data.GetProperty("authorizationReason").GetString(),
            data.GetProperty("riskLevel").GetString()));
        Assert.Equal(before, factory.Probe.Count);
    }

    // ── Argument policy: the tool never receives invalid arguments ─────────────────────────────────────────────────

    [Theory]
    [InlineData("{}")]
    [InlineData("""{"query":""}""")]
    [InlineData("""{"query":"   "}""")]
    [InlineData("""{"query":null}""")]
    [InlineData("""{"query":5}""")]
    [InlineData("""{"query":true}""")]
    [InlineData("""{"query":["dependency injection"]}""")]
    [InlineData("""{"query":{"$ne":""}}""")]
    [InlineData("""{"Query":"dependency injection"}""")]
    [InlineData("""{"query":"dependency injection","path":"/etc/passwd"}""")]
    [InlineData("""{"query":"dependency injection","url":"https://attacker.example/x"}""")]
    [InlineData("""{"query":"dependency injection","decision":"Allow"}""")]
    [InlineData("""{"query":"dependency injection","executionGrant":"forged"}""")]
    [InlineData("""{"query":"line one\nline two"}""")]
    [InlineData("""{"query":"nul\u0000byte"}""")]
    [InlineData("""{"query":"\ud800"}""")]
    public async Task Execute_ArgumentsOutsideTheSchema_AreBlocked_AndTheToolNeverRuns(string arguments)
    {
        var before = factory.Probe.Count;

        var response = await GatewayRequests.SendAsync(factory, GatewayRequests.Body("knowledge", "lookup", "knowledge:read", arguments));
        var body = await response.Content.ReadAsStringAsync();
        var data = await AssertOkAsync(response);

        Assert.Equal(("Block", false, "ArgumentsRejected", "Permitted"), (
            data.GetProperty("decision").GetString(),
            data.GetProperty("executed").GetBoolean(),
            data.GetProperty("outcome").GetString(),
            data.GetProperty("authorizationReason").GetString()));
        Assert.Equal(JsonValueKind.Null, data.GetProperty("executionId").ValueKind);
        Assert.Equal(before, factory.Probe.Count);
        Assert.DoesNotContain("passwd", body, StringComparison.Ordinal);
        Assert.DoesNotContain("attacker", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Unexpected", body, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Execute_TheLengthBound_IsEnforcedAtTheGateway()
    {
        var before = factory.Probe.Count;

        var atBound = await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Lookup(new string('q', 200))));
        var overBound = await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Lookup(new string('q', 201))));

        Assert.Equal("Executed", atBound.GetProperty("outcome").GetString());
        Assert.Equal("ArgumentsRejected", overBound.GetProperty("outcome").GetString());
        Assert.Equal(before + 1, factory.Probe.Count);
    }

    [Theory]
    [InlineData("""{"tool":"knowledge","action":"lookup","capability":"knowledge:read"}""")]
    [InlineData("""{"tool":"knowledge","action":"lookup","capability":"knowledge:read","arguments":null}""")]
    [InlineData("""{"tool":"knowledge","action":"lookup","capability":"knowledge:read","arguments":[]}""")]
    [InlineData("""{"tool":"knowledge","action":"lookup","capability":"knowledge:read","arguments":"dependency injection"}""")]
    [InlineData("""{"tool":"knowledge","action":"lookup","capability":"knowledge:read","arguments":42}""")]
    public async Task Execute_ArgumentsThatAreNotAnObject_Return422_AndNothingRuns(string body)
    {
        var before = factory.Probe.Count;

        var response = await GatewayRequests.SendAsync(factory, body);

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.UnprocessableEntity, "Validation.Failed");
        Assert.True(problem.GetProperty("errors").TryGetProperty("arguments", out _), problem.GetRawText());
        Assert.False(problem.TryGetProperty("data", out _));
        Assert.Equal(before, factory.Probe.Count);
    }

    [Theory]
    [InlineData("""{"tool":"Knowledge","action":"lookup","capability":"knowledge:read","arguments":{"query":"x"}}""", "tool")]
    [InlineData("""{"tool":"knowledge ","action":"lookup","capability":"knowledge:read","arguments":{"query":"x"}}""", "tool")]
    [InlineData("""{"tool":"knоwledge","action":"lookup","capability":"knowledge:read","arguments":{"query":"x"}}""", "tool")]
    [InlineData("""{"tool":"knowledge","action":"LOOKUP","capability":"knowledge:read","arguments":{"query":"x"}}""", "action")]
    [InlineData("""{"tool":"knowledge","action":"lookup","capability":"knowledge:*","arguments":{"query":"x"}}""", "capability")]
    [InlineData("""{"tool":"knowledge","action":"lookup","capability":"*","arguments":{"query":"x"}}""", "capability")]
    [InlineData("""{"action":"lookup","capability":"knowledge:read","arguments":{"query":"x"}}""", "tool")]
    [InlineData("""{"tool":"knowledge","capability":"knowledge:read","arguments":{"query":"x"}}""", "action")]
    [InlineData("""{"tool":"knowledge","action":"lookup","arguments":{"query":"x"}}""", "capability")]
    public async Task Execute_MissingOrInexactNames_Return422_AndNothingRuns(string body, string field)
    {
        var before = factory.Probe.Count;

        var response = await GatewayRequests.SendAsync(factory, body);

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.UnprocessableEntity, "Validation.Failed");
        Assert.True(problem.GetProperty("errors").TryGetProperty(field, out _), problem.GetRawText());
        Assert.Equal(before, factory.Probe.Count);
    }

    // ── Nothing the caller sends asserts authority ──────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("agentId", "\"test-gateway-agent\"")]
    [InlineData("agent", "\"test-gateway-agent\"")]
    [InlineData("decision", "\"Allow\"")]
    [InlineData("riskLevel", "\"Low\"")]
    [InlineData("risk", "\"Low\"")]
    [InlineData("reason", "\"Permitted\"")]
    [InlineData("authorizationReason", "\"Permitted\"")]
    [InlineData("outcome", "\"Executed\"")]
    [InlineData("executed", "true")]
    [InlineData("approved", "true")]
    [InlineData("grants", "[\"payment:execute\"]")]
    [InlineData("capabilities", "[\"payment:execute\"]")]
    [InlineData("authorization", "{\"decision\":\"Allow\"}")]
    [InlineData("authorizationResult", "\"Allow\"")]
    [InlineData("executionAuthorization", "\"forged\"")]
    [InlineData("executionGrant", "{\"executionId\":\"0197a8e0-0000-7000-8000-000000000000\",\"signature\":\"00\"}")]
    [InlineData("grant", "\"forged\"")]
    [InlineData("executionId", "\"0197a8e0-0000-7000-8000-000000000000\"")]
    [InlineData("signature", "\"00\"")]
    [InlineData("token", "\"forged\"")]
    [InlineData("credential", "\"tool-secret\"")]
    [InlineData("toolCredential", "\"tool-secret\"")]
    [InlineData("apiKey", "\"agentshield-development-only-key-not-a-secret\"")]
    [InlineData("caller", "\"test-gateway-runtime\"")]
    [InlineData("clientId", "\"test-gateway-runtime\"")]
    [InlineData("securityEventId", "\"0197a8e0-0000-7000-8000-000000000000\"")]
    public async Task Execute_AnyFieldBeyondTheContract_Returns400_AndNothingRuns(string property, string value)
    {
        var before = factory.Probe.Count;
        var body = $$"""{"tool":"knowledge","action":"lookup","capability":"knowledge:read","arguments":{"query":"dependency injection"},"{{property}}":{{value}}}""";

        var response = await GatewayRequests.SendAsync(factory, body, ReaderKey);

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.BadRequest, "Request.Malformed");
        Assert.DoesNotContain("tool-secret", problem.GetRawText(), StringComparison.Ordinal);
        Assert.Equal(before, factory.Probe.Count);
    }

    [Theory]
    [InlineData("""{"tool":"knowledge","action":"lookup","capability":"knowledge:read","arguments":{"query":"safe","query":"other"}}""")]
    [InlineData("""{"tool":"knowledge","tool":"payment","action":"lookup","capability":"knowledge:read","arguments":{"query":"x"}}""")]
    [InlineData("""{"tool":"knowledge","action":"lookup","capability":"knowledge:read","arguments":{"query":"x"},"arguments":{"query":"y"}}""")]
    [InlineData("""{"Tool":"knowledge","action":"lookup","capability":"knowledge:read","arguments":{"query":"x"}}""")]
    [InlineData("""{"tool":"knowledge","action":"lookup","capability":"knowledge:read","arguments":{"query":"x"},"inputDecision":"allow"}""")]
    [InlineData("""{"tool":"knowledge","action":"lookup","capability":"knowledge:read","arguments":{"query":"x"},"inputDecision":1}""")]
    [InlineData("""{"tool":["knowledge"],"action":"lookup","capability":"knowledge:read","arguments":{"query":"x"}}""")]
    [InlineData("""{"tool":"knowledge","action":"lookup","capability":"knowledge:read","arguments":{"query":"x"}""")]
    [InlineData("""not json""")]
    public async Task Execute_AmbiguousOrMalformedBody_Returns400_AndNothingRuns(string body)
    {
        var before = factory.Probe.Count;

        var response = await GatewayRequests.SendAsync(factory, body);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.BadRequest, "Request.Malformed");
        Assert.Equal(before, factory.Probe.Count);
    }

    // ── Trusted agent identity ──────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Execute_TheAgentIsTheCredentials_TheSameBodyDecidesPerKey()
    {
        // Both credentials send the identical request: each acts as its own agent, and only one holds knowledge:read.
        var before = factory.Probe.Count;
        var body = GatewayRequests.Lookup("least privilege");

        var gateway = await AssertOkAsync(await GatewayRequests.SendAsync(factory, body, GatewayKey));
        var reader = await AssertOkAsync(await GatewayRequests.SendAsync(factory, body, ReaderKey));

        Assert.Equal("Executed", gateway.GetProperty("outcome").GetString());
        Assert.Equal(("Block", "CapabilityNotGranted"), (reader.GetProperty("decision").GetString(), reader.GetProperty("authorizationReason").GetString()));
        Assert.Equal(before + 1, factory.Probe.Count);
    }

    [Fact]
    public async Task Execute_ACredentialCannotNameAnotherAgent()
    {
        // The reader runtime tries to borrow the gateway agent's knowledge:read by naming it: there is no field for that.
        var before = factory.Probe.Count;
        var body = $$$"""{"agentId":"{{{GatewayAgent}}}","tool":"knowledge","action":"lookup","capability":"knowledge:read","arguments":{"query":"x"}}""";

        await ProblemAssertions.AssertProblemAsync(await GatewayRequests.SendAsync(factory, body, ReaderKey), HttpStatusCode.BadRequest, "Request.Malformed");
        Assert.Equal(before, factory.Probe.Count);
    }

    // ── Access ──────────────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Execute_Anonymous_Returns401_AndNothingRuns()
    {
        var before = factory.Probe.Count;

        await ProblemAssertions.AssertProblemAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Lookup("di"), apiKey: null), HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
        await ProblemAssertions.AssertProblemAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Lookup("di"), apiKey: "not-a-valid-key-0123456789abcdefghijklmn"), HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
        Assert.Equal(before, factory.Probe.Count);
    }

    [Theory]
    [InlineData(TestApiKeys.Analyzer)]
    [InlineData(TestApiKeys.ActivityReader)]
    [InlineData(TestApiKeys.AgentRuntime)]
    [InlineData(TestApiKeys.OtherRuntime)]
    [InlineData(TestApiKeys.NoPermissions)]
    public async Task Execute_ClientWithoutToolExecute_Returns403_AndNothingRuns(string apiKey)
    {
        var before = factory.Probe.Count;

        var problem = await ProblemAssertions.AssertProblemAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Lookup("di"), apiKey), HttpStatusCode.Forbidden, "Auth.Forbidden");

        Assert.DoesNotContain("tool:execute", problem.GetRawText(), StringComparison.Ordinal);
        Assert.Equal(before, factory.Probe.Count);
    }

    [Fact]
    public async Task GatewayCredential_CannotAuthorizeAnalyzeOrReadActivity()
    {
        using var client = AnalyzeRequests.CreateAnonymousClient(factory);
        using var activity = new HttpRequestMessage(HttpMethod.Get, ActivityRoute);
        activity.Headers.Add(TestApiKeys.HeaderName, GatewayKey);

        await ProblemAssertions.AssertProblemAsync(await AgentRequests.SendAsync(factory, AgentRequests.Body(GatewayAgent, "knowledge", "lookup", "knowledge:read"), GatewayKey), HttpStatusCode.Forbidden, "Auth.Forbidden");
        await ProblemAssertions.AssertProblemAsync(await client.SendAsync(AnalyzeRequests.Create(apiKeys: GatewayKey)), HttpStatusCode.Forbidden, "Auth.Forbidden");
        await ProblemAssertions.AssertProblemAsync(await client.SendAsync(activity), HttpStatusCode.Forbidden, "Auth.Forbidden");
    }

    // ── Complete mediation ──────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void EndpointInventory_TheGatewayIsTheOnlyEndpointThatCanExecute_AndRequiresExactlyToolExecute()
    {
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>().ToArray();

        var gateway = Assert.Single(endpoints, candidate => candidate.RoutePattern.RawText == "api/v1/agent/tools/execute");
        Assert.Null(gateway.Metadata.GetMetadata<IAllowAnonymous>());
        Assert.Equal([AuthorizationPolicies.ToolExecute], gateway.Metadata.GetOrderedMetadata<IAuthorizeData>().Select(authorize => authorize.Policy).OfType<string>());
        Assert.Equal(["POST"], gateway.Metadata.GetMetadata<HttpMethodMetadata>()!.HttpMethods);

        // No other endpoint is reachable with the tool:execute permission, and none sits under the tools route.
        Assert.Single(endpoints, endpoint => endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>().Any(authorize => authorize.Policy == AuthorizationPolicies.ToolExecute));
        Assert.Single(endpoints, endpoint => endpoint.RoutePattern.RawText?.Contains("tools", StringComparison.OrdinalIgnoreCase) == true);
    }

    [Fact]
    public void TheToolExecutors_AreReachableOnlyThroughTheExecutionAuthority()
    {
        // The only executor registered is the probed real one; nothing resolves an executor's concrete type.
        var executors = factory.Services.GetServices<IToolExecutor>().ToArray();
        Assert.Equal(("knowledge", "lookup"), (Assert.Single(executors).Tool.Value, executors[0].Action.Value));
        Assert.Equal("ExecutionGrantAuthority", factory.Services.GetRequiredService<IToolExecutionAuthority>().GetType().Name);
    }

    // ── Response and recording ──────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Execute_Response_HasExactlyTheDocumentedFields_AndNeverEchoesTheRequest()
    {
        const string Marker = "zq7gatewayecho";
        var allowed = await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Lookup("dependency injection " + Marker)));
        var blockedResponse = await GatewayRequests.SendAsync(factory, GatewayRequests.Body("zq7gatewayecho-tool", "zq7gatewayecho-action", "zq7gatewayecho:cap", $$"""{"{{Marker}}":"{{Marker}}"}"""));
        var blockedBody = await blockedResponse.Content.ReadAsStringAsync();
        var blocked = await AssertOkAsync(blockedResponse);

        string[] fields = ["approvalId", "authorizationReason", "decision", "executed", "executionId", "outcome", "result", "riskLevel", "securityEventId"];
        Assert.Equal(fields, Names(allowed));
        Assert.Equal(fields, Names(blocked));
        Assert.Equal(["found", "text"], Names(allowed.GetProperty("result")));
        Assert.DoesNotContain(Marker, allowed.GetRawText(), StringComparison.Ordinal);
        Assert.DoesNotContain(Marker, blockedBody, StringComparison.Ordinal);
        Assert.Equal(("Block", "UnknownTool"), (blocked.GetProperty("decision").GetString(), blocked.GetProperty("authorizationReason").GetString()));
    }

    [Fact]
    public async Task Execution_IsListedInActivity_OnceAsMetadata_WithWhatTheCallerReceived()
    {
        var correlationId = "gw-act-" + Guid.NewGuid().ToString("N")[..10];
        var data = await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Lookup("complete mediation"), correlationId: correlationId));

        var item = await FindAsync(factory, correlationId);

        Assert.Equal(data.GetProperty("securityEventId").GetGuid(), item.GetProperty("securityEventId").GetGuid());
        Assert.Equal(("ToolExecution", "Allow", "Low"), (item.GetProperty("kind").GetString(), item.GetProperty("decision").GetString(), item.GetProperty("risk").GetProperty("level").GetString()));
        Assert.Equal(JsonValueKind.Null, item.GetProperty("risk").GetProperty("score").ValueKind);
        Assert.Equal(JsonValueKind.Null, item.GetProperty("aiAnalysis").ValueKind);
        var execution = item.GetProperty("toolExecution");
        Assert.Equal(["executed", "executionId", "outcome"], Names(execution));
        Assert.Equal(("Executed", true, data.GetProperty("executionId").GetGuid()), (execution.GetProperty("outcome").GetString(), execution.GetProperty("executed").GetBoolean(), execution.GetProperty("executionId").GetGuid()));
        var action = item.GetProperty("agentAction");
        Assert.Equal((GatewayAgent, "knowledge", "lookup", "knowledge:read", "Permitted"), (
            action.GetProperty("agentId").GetString(),
            action.GetProperty("tool").GetString(),
            action.GetProperty("action").GetString(),
            action.GetProperty("capability").GetString(),
            action.GetProperty("reason").GetString()));
        Assert.DoesNotContain("Complete mediation:", item.GetRawText(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Activity_NeverHoldsTheArgumentsTheResultOrMadeUpNames()
    {
        const string Marker = "zq7gwactivity";
        var correlation = "gw-act-priv-" + Guid.NewGuid().ToString("N")[..8];
        await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Lookup("idempotency " + Marker), correlationId: correlation + "-a"));
        await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Lookup("idempotency"), correlationId: correlation + "-b"));
        await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Body("knowledge", "lookup", "knowledge:read", $$"""{"query":"x","{{Marker}}":"{{Marker}}"}"""), correlationId: correlation + "-c"));
        await AssertOkAsync(await GatewayRequests.SendAsync(factory, GatewayRequests.Body(Marker, "lookup", Marker + ":read", "{}"), correlationId: correlation + "-d"));

        string[] suffixes = ["-a", "-b", "-c", "-d"];
        var items = suffixes.Select(suffix => FindAsync(factory, correlation + suffix)).ToArray();
        var records = await Task.WhenAll(items);

        Assert.All(records, item => Assert.DoesNotContain(Marker, item.GetRawText(), StringComparison.Ordinal));
        Assert.All(records, item => Assert.DoesNotContain("Idempotency:", item.GetRawText(), StringComparison.Ordinal));
        Assert.Equal("ArgumentsRejected", records[2].GetProperty("toolExecution").GetProperty("outcome").GetString());
        var unknown = records[3].GetProperty("agentAction");
        Assert.Equal((GatewayAgent, JsonValueKind.Null, JsonValueKind.Null), (unknown.GetProperty("agentId").GetString(), unknown.GetProperty("tool").ValueKind, unknown.GetProperty("capability").ValueKind));
    }

    [Theory]
    [InlineData(ToolGatewayEventType.ToolAuthorizationRequested, 0)]
    [InlineData(ToolGatewayEventType.ToolAuthorizationAllowed, 0)]
    [InlineData(ToolGatewayEventType.ToolExecutionStarted, 0)]
    [InlineData(ToolGatewayEventType.ToolExecutionCompleted, 1)]
    public async Task Execute_RecordingFailsAtAStage_Returns500WithNoDecisionOrResult_AndTheToolRunsOnlyAfterItsStartWasRecorded(ToolGatewayEventType stage, int runs)
    {
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.AddSingleton<IToolGatewayEventSink>(new FailingAtStage(stage))));
        var probe = host.Services.GetRequiredService<ToolProbe>();

        var response = await GatewayRequests.SendAsync(host, GatewayRequests.Lookup("dependency injection"), correlationId: "gw-sink-down");

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.InternalServerError, "Server.Unexpected");
        Assert.False(problem.TryGetProperty("data", out _));
        Assert.DoesNotContain("Dependency injection:", problem.GetRawText(), StringComparison.Ordinal);
        Assert.DoesNotContain(FailingAtStage.Message, problem.GetRawText(), StringComparison.Ordinal);
        Assert.Equal(runs, probe.Count);
    }

    [Fact]
    public async Task Execute_TheActivityStoreFails_NoDecisionIsReturned_AndNothingRuns()
    {
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.AddSingleton<ISecurityActivityStore, FailingStore>()));
        var probe = host.Services.GetRequiredService<ToolProbe>();

        var response = await GatewayRequests.SendAsync(host, GatewayRequests.Body("email", "send", "email:send"));

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.InternalServerError, "Server.Unexpected");
        Assert.False(problem.TryGetProperty("data", out _));
        Assert.Equal(0, probe.Count);
    }

    [Fact]
    public async Task Production_TheGatewayWorksOutsideDevelopment_AndNoCommittedClientMayCallIt()
    {
        using var production = new ProductionGatewayFactory();

        var data = await AssertOkAsync(await GatewayRequests.SendAsync(production, GatewayRequests.Lookup("fail closed")));
        await ProblemAssertions.AssertProblemAsync(await GatewayRequests.SendAsync(production, GatewayRequests.Lookup("fail closed"), TestApiKeys.Development), HttpStatusCode.Unauthorized, "Auth.Unauthenticated");

        Assert.Equal("Executed", data.GetProperty("outcome").GetString());
        Assert.Equal(1, production.Probe.Count);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────────────────────────────────────────

    private static async Task<JsonElement> FindAsync(WebApplicationFactory<Program> host, string correlationId)
    {
        using var client = AnalyzeRequests.CreateAnonymousClient(host);
        using var request = new HttpRequestMessage(HttpMethod.Get, ActivityRoute + "?pageSize=100");
        request.Headers.Add(TestApiKeys.HeaderName, TestApiKeys.ActivityReader);
        var data = await AssertOkAsync(await client.SendAsync(request));
        return Assert.Single(data.GetProperty("items").EnumerateArray(), item => item.GetProperty("correlationId").GetString() == correlationId);
    }

    private static async Task<JsonElement> AssertOkAsync(HttpResponseMessage response)
    {
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, body);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        using var document = JsonDocument.Parse(body);
        var meta = document.RootElement.GetProperty("meta");
        Assert.Equal(Assert.Single(response.Headers.GetValues("X-Correlation-ID")), meta.GetProperty("correlationId").GetString());
        return document.RootElement.GetProperty("data").Clone();
    }

    private static string[] Names(JsonElement element) => [.. element.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal)];

    private sealed class FailingAtStage(ToolGatewayEventType stage) : IToolGatewayEventSink
    {
        public const string Message = "zq7-gateway-sink-failure";

        public ValueTask PublishAsync(ToolGatewayEvent toolGatewayEvent, CancellationToken cancellationToken) =>
            toolGatewayEvent.Type == stage ? ValueTask.FromException(new InvalidOperationException(Message)) : ValueTask.CompletedTask;
    }

    private sealed class FailingStore : ISecurityActivityStore
    {
        public ValueTask AppendAsync(SecurityActivityRecord record, CancellationToken cancellationToken) =>
            ValueTask.FromException(new InvalidOperationException("zq7-store-failure"));

        public ValueTask<SecurityActivitySlice> QueryAsync(SecurityActivityQuery query, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    /// <summary>The gateway agents in the Production environment: appsettings.json plus the test clients and agents.</summary>
    private sealed class ProductionGatewayFactory : GatewayApiFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.UseEnvironment("Production");
            builder.UseSetting("Cors:AllowedOrigins:0", ProductionApiFactory.AllowedOrigin);
        }
    }
}
