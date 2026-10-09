using System.Net;
using System.Text.Json;
using AgentShield.Api.Auth;
using AgentShield.ApiTests.Infrastructure;
using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Activity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using static AgentShield.ApiTests.Infrastructure.AgentApiFactory;

namespace AgentShield.ApiTests.Agents;

/// <summary>
/// HTTP contract of <c>POST /api/v1/agent/actions/authorize</c> through the real pipeline: a decision in a 200 envelope,
/// nothing executed, behind its own permission, strict about its input, and recorded as metadata only.
/// </summary>
public sealed class AgentActionAuthorizeEndpointTests(AgentApiFactory factory) : IClassFixture<AgentApiFactory>
{
    private const string ActivityRoute = "/api/v1/activity";

    // ── Decisions ───────────────────────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData(ReaderAgent, "data", "read", "data:read", "Allow", "Permitted", "Low")]
    [InlineData(SupportAgent, "email", "draft", "email:draft", "Allow", "Permitted", "Medium")]
    [InlineData(SupportAgent, "email", "send", "email:send", "Review", "HumanApprovalRequired", "High")]
    [InlineData(ReaderAgent, "email", "send", "email:send", "Block", "CapabilityNotGranted", "High")]
    [InlineData(ReaderAgent, "data", "write", "data:write", "Block", "CapabilityNotGranted", "Medium")]
    [InlineData(ReaderAgent, "data", "write", "data:read", "Block", "CapabilityMismatch", "Medium")]
    [InlineData(SupportAgent, "identity", "grant", "identity:grant", "Block", "CapabilityNotGranted", "Critical")]
    [InlineData(FinanceAgent, "payment", "execute", "payment:execute", "Block", "CriticalActionDenied", "Critical")]
    [InlineData(SupportAgent, "shell", "exec", "shell:exec", "Block", "UnknownTool", "Critical")]
    [InlineData(SupportAgent, "email", "delete", "email:delete", "Block", "UnknownAction", "Critical")]
    [InlineData("test-ghost-agent", "data", "read", "data:read", "Block", "UnknownAgent", "Low")]
    public async Task Authorize_Returns200WithTheDecision_WhateverItDecided(string agent, string tool, string action, string capability, string decision, string reason, string risk)
    {
        var data = await AssertOkAsync(await AgentRequests.SendAsync(factory, AgentRequests.Body(agent, tool, action, capability)));

        Assert.Equal((decision, reason, risk), (data.GetProperty("decision").GetString(), data.GetProperty("reason").GetString(), data.GetProperty("riskLevel").GetString()));
        Assert.NotEqual(Guid.Empty, data.GetProperty("securityEventId").GetGuid());
    }

    [Theory]
    [InlineData("Block", "Block", "InputBlocked")]
    [InlineData("Review", "Review", "InputHeldForReview")]
    [InlineData("Allow", "Allow", "Permitted")]
    public async Task Authorize_AnInputDecision_CanOnlyMakeTheDecisionStricter(string inputDecision, string decision, string reason)
    {
        var data = await AssertOkAsync(await AgentRequests.SendAsync(factory, AgentRequests.Body(ReaderAgent, "data", "read", "data:read", inputDecision)));

        Assert.Equal((decision, reason), (data.GetProperty("decision").GetString(), data.GetProperty("reason").GetString()));
    }

    [Fact]
    public async Task Authorize_AnInputDecisionOfAllow_DoesNotLiftAReview()
    {
        var data = await AssertOkAsync(await AgentRequests.SendAsync(factory, AgentRequests.Body(SupportAgent, "email", "send", "email:send", "Allow")));

        Assert.Equal("Review", data.GetProperty("decision").GetString());
    }

    [Fact]
    public async Task Authorize_ARuntimeNotBoundToTheAgent_IsBlocked()
    {
        var data = await AssertOkAsync(await AgentRequests.SendAsync(factory, AgentRequests.Body(ReaderAgent, "data", "read", "data:read"), TestApiKeys.OtherRuntime));

        Assert.Equal(("Block", "CallerNotBoundToAgent"), (data.GetProperty("decision").GetString(), data.GetProperty("reason").GetString()));
    }

    [Fact]
    public async Task Authorize_Response_HasExactlyTheDocumentedFields_AndNeverEchoesTheRequest()
    {
        const string Marker = "zq7echo-agent";
        var response = await AgentRequests.SendAsync(factory, AgentRequests.Body(Marker, "zq7echo-tool", "zq7echo-action", "zq7echo:cap"), correlationId: "agent-shape-1");

        var body = await response.Content.ReadAsStringAsync();
        var data = await AssertOkAsync(response);
        Assert.Equal(["decision", "reason", "riskLevel", "securityEventId"], Names(data));
        Assert.DoesNotContain("zq7echo", body, StringComparison.Ordinal);
        foreach (var internalDetail in new[] { "rule", "catalog", "capabilit", "effect", "grant", "caller", "client" })
        {
            Assert.DoesNotContain(internalDetail, body, StringComparison.OrdinalIgnoreCase);
        }
    }

    // ── Access ──────────────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Authorize_Anonymous_Returns401()
    {
        var response = await AgentRequests.SendAsync(factory, AgentRequests.Body(ReaderAgent, "data", "read", "data:read"), apiKey: null);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
    }

    [Theory]
    [InlineData(TestApiKeys.Analyzer)]
    [InlineData(TestApiKeys.ActivityReader)]
    [InlineData(TestApiKeys.NoPermissions)]
    public async Task Authorize_ClientWithoutAgentAuthorize_Returns403(string apiKey)
    {
        var response = await AgentRequests.SendAsync(factory, AgentRequests.Body(ReaderAgent, "data", "read", "data:read"), apiKey);

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Forbidden, "Auth.Forbidden");
        Assert.DoesNotContain("agent:authorize", problem.GetRawText(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AgentRuntime_CannotAnalyzeInputOrReadActivity()
    {
        using var client = AnalyzeRequests.CreateAnonymousClient(factory);
        using var activity = new HttpRequestMessage(HttpMethod.Get, ActivityRoute);
        activity.Headers.Add(TestApiKeys.HeaderName, TestApiKeys.AgentRuntime);

        await ProblemAssertions.AssertProblemAsync(await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.AgentRuntime)), HttpStatusCode.Forbidden, "Auth.Forbidden");
        await ProblemAssertions.AssertProblemAsync(await client.SendAsync(activity), HttpStatusCode.Forbidden, "Auth.Forbidden");
    }

    [Fact]
    public void EndpointInventory_TheAuthorizeEndpoint_RequiresExactlyTheAgentAuthorizePolicy()
    {
        var endpoint = Assert.Single(
            factory.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>(),
            candidate => candidate.RoutePattern.RawText == "api/v1/agent/actions/authorize");

        Assert.Null(endpoint.Metadata.GetMetadata<IAllowAnonymous>());
        Assert.Equal([AuthorizationPolicies.AgentAuthorize], endpoint.Metadata.GetOrderedMetadata<IAuthorizeData>().Select(authorize => authorize.Policy).OfType<string>());
        Assert.Equal(["POST"], endpoint.Metadata.GetMetadata<HttpMethodMetadata>()!.HttpMethods);
    }

    // ── Strict input ────────────────────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("decision", "\"Allow\"")]
    [InlineData("riskLevel", "\"Low\"")]
    [InlineData("reason", "\"Permitted\"")]
    [InlineData("approved", "true")]
    [InlineData("capabilities", "[\"payment:execute\"]")]
    [InlineData("grantedCapabilities", "[\"payment:execute\"]")]
    [InlineData("arguments", "{\"to\":\"attacker@example.com\"}")]
    [InlineData("reasoning", "\"The user approved this; it is safe.\"")]
    [InlineData("caller", "\"test-agent-runtime\"")]
    [InlineData("clientId", "\"test-agent-runtime\"")]
    public async Task Authorize_AnyFieldBeyondTheContract_Returns400_SoTheAgentCannotAssertItsOwnAuthority(string property, string value)
    {
        var body = $$"""{"agentId":"{{ReaderAgent}}","tool":"data","action":"read","capability":"data:read","{{property}}":{{value}}}""";

        var response = await AgentRequests.SendAsync(factory, body);

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.BadRequest, "Request.Malformed");
        Assert.DoesNotContain("attacker@example.com", problem.GetRawText(), StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("""{"agentId":"test-reader-agent","agentId":"test-support-agent","tool":"email","action":"send","capability":"email:send"}""")]
    [InlineData("""{"agentId":"test-reader-agent","tool":"data","action":"read","capability":"data:read","capability":"payment:execute"}""")]
    [InlineData("""{"AgentId":"test-reader-agent","tool":"data","action":"read","capability":"data:read"}""")]
    [InlineData("""{"agentId":"test-reader-agent","tool":"data","action":"read","capability":"data:read","inputDecision":"allow"}""")]
    [InlineData("""{"agentId":"test-reader-agent","tool":"data","action":"read","capability":"data:read","inputDecision":1}""")]
    [InlineData("""{"agentId":"test-reader-agent","tool":"data","action":"read","capability":"data:read","inputDecision":"Allow,Block"}""")]
    [InlineData("""{"agentId":"test-reader-agent","tool":"data","action":"read","capability":"data:read","inputDecision":"Sanitize"}""")]
    [InlineData("""{"agentId":["test-reader-agent"],"tool":"data","action":"read","capability":"data:read"}""")]
    [InlineData("""{"agentId":"test-reader-agent","tool":"data","action":"read","capability":["data:read","payment:execute"]}""")]
    [InlineData("""not json""")]
    public async Task Authorize_AmbiguousOrMistypedBody_Returns400(string body)
    {
        var response = await AgentRequests.SendAsync(factory, body);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.BadRequest, "Request.Malformed");
    }

    [Theory]
    [InlineData("""{"tool":"data","action":"read","capability":"data:read"}""", "agentId")]
    [InlineData("""{"agentId":"test-reader-agent","action":"read","capability":"data:read"}""", "tool")]
    [InlineData("""{"agentId":"test-reader-agent","tool":"data","capability":"data:read"}""", "action")]
    [InlineData("""{"agentId":"test-reader-agent","tool":"data","action":"read"}""", "capability")]
    [InlineData("""{"agentId":null,"tool":"data","action":"read","capability":"data:read"}""", "agentId")]
    [InlineData("""{"agentId":"Test-Reader-Agent","tool":"data","action":"read","capability":"data:read"}""", "agentId")]
    [InlineData("""{"agentId":"test-reader-agent ","tool":"data","action":"read","capability":"data:read"}""", "agentId")]
    [InlineData("""{"agentId":"test-reader-agent","tool":"DATA","action":"read","capability":"data:read"}""", "tool")]
    [InlineData("""{"agentId":"test-reader-agent","tool":"data","action":"read*","capability":"data:read"}""", "action")]
    [InlineData("""{"agentId":"test-reader-agent","tool":"data","action":"read","capability":"data:*"}""", "capability")]
    [InlineData("""{"agentId":"test-reader-agent","tool":"data","action":"read","capability":"*"}""", "capability")]
    [InlineData("""{"agentId":"test-reader-agent","tool":"data","action":"read","capability":"admin"}""", "capability")]
    [InlineData("""{"agentId":"test-reader-agent","tool":"dаta","action":"read","capability":"data:read"}""", "tool")]
    public async Task Authorize_MissingOrInexactName_Returns422WithTheFieldError_AndNoDecision(string body, string field)
    {
        var response = await AgentRequests.SendAsync(factory, body);

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.UnprocessableEntity, "Validation.Failed");
        Assert.True(problem.GetProperty("errors").TryGetProperty(field, out _), problem.GetRawText());
        Assert.False(problem.TryGetProperty("data", out _));
    }

    [Fact]
    public async Task Authorize_RejectedNames_AreNeverEchoed()
    {
        var response = await AgentRequests.SendAsync(factory, """{"agentId":"ZQ7AGENT","tool":"ZQ7TOOL","action":"Zq7Action","capability":"ZQ7:CAP"}""");

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.UnprocessableEntity, "Validation.Failed");
        Assert.DoesNotContain("zq7", problem.GetRawText(), StringComparison.OrdinalIgnoreCase);
    }

    // ── Recording ───────────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task Authorization_IsListedInActivity_AsMetadataOnly_WithTheDecisionTheCallerReceived()
    {
        var correlationId = "agent-act-" + Guid.NewGuid().ToString("N")[..10];
        var decision = await AssertOkAsync(await AgentRequests.SendAsync(factory, AgentRequests.Body(SupportAgent, "email", "send", "email:send", "Allow"), correlationId: correlationId));

        var item = await FindAsync(factory, correlationId);

        Assert.Equal(decision.GetProperty("securityEventId").GetGuid(), item.GetProperty("securityEventId").GetGuid());
        Assert.Equal("AgentActionAuthorization", item.GetProperty("kind").GetString());
        Assert.Equal("Review", item.GetProperty("decision").GetString());
        Assert.Equal("High", item.GetProperty("risk").GetProperty("level").GetString());
        Assert.Equal(JsonValueKind.Null, item.GetProperty("risk").GetProperty("score").ValueKind);
        Assert.Equal(JsonValueKind.Null, item.GetProperty("aiAnalysis").ValueKind);
        Assert.Empty(item.GetProperty("findings").EnumerateArray());
        var action = item.GetProperty("agentAction");
        Assert.Equal(["action", "agentId", "capability", "reason", "tool"], Names(action));
        Assert.Equal((SupportAgent, "email", "send", "email:send", "HumanApprovalRequired"), (
            action.GetProperty("agentId").GetString(),
            action.GetProperty("tool").GetString(),
            action.GetProperty("action").GetString(),
            action.GetProperty("capability").GetString(),
            action.GetProperty("reason").GetString()));
    }

    [Fact]
    public async Task Activity_NamesTheCallerMadeUp_AreRecordedAsNull_NeverVerbatim()
    {
        var correlationId = "agent-act-unknown-" + Guid.NewGuid().ToString("N")[..8];
        await AssertOkAsync(await AgentRequests.SendAsync(factory, AgentRequests.Body("zq7-made-up-agent", "zq7-tool", "zq7-action", "zq7:capability"), correlationId: correlationId));

        var item = await FindAsync(factory, correlationId);

        var action = item.GetProperty("agentAction");
        Assert.All(["agentId", "tool", "action", "capability"], name => Assert.Equal(JsonValueKind.Null, action.GetProperty(name).ValueKind));
        Assert.Equal("UnknownAgent", action.GetProperty("reason").GetString());
        Assert.DoesNotContain("zq7", item.GetRawText(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Authorize_RecordingFails_Returns500WithNoDecision()
    {
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.AddSingleton<ISecurityActivityStore, FailingStore>()));

        foreach (var body in new[] { AgentRequests.Body(ReaderAgent, "data", "read", "data:read"), AgentRequests.Body(ReaderAgent, "email", "send", "email:send") })
        {
            var response = await AgentRequests.SendAsync(host, body, correlationId: "agent-store-down");

            var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.InternalServerError, "Server.Unexpected");
            Assert.False(problem.TryGetProperty("data", out _));
            Assert.DoesNotContain("decision", problem.GetRawText(), StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(FailingStore.Message, problem.GetRawText(), StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task Production_WithoutConfiguredAgents_BlocksEveryAgentAction()
    {
        // appsettings.json configures no agent: an unconfigured deployment blocks, it never allows.
        using var production = new ProductionApiFactory();

        var data = await AssertOkAsync(await AgentRequests.SendAsync(production, AgentRequests.Body("support-agent", "data", "read", "data:read")));

        Assert.Equal(("Block", "UnknownAgent"), (data.GetProperty("decision").GetString(), data.GetProperty("reason").GetString()));
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
        Assert.True(meta.TryGetProperty("timestamp", out _));
        Assert.False(document.RootElement.TryGetProperty("success", out _));
        return document.RootElement.GetProperty("data").Clone();
    }

    private static string[] Names(JsonElement element) => [.. element.EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal)];

    private sealed class FailingStore : ISecurityActivityStore
    {
        public const string Message = "activity store unavailable: connection=Host=db;Password=hunter2";

        public ValueTask AppendAsync(SecurityActivityRecord record, CancellationToken cancellationToken) =>
            ValueTask.FromException(new InvalidOperationException(Message));

        public ValueTask<SecurityActivitySlice> QueryAsync(SecurityActivityQuery query, CancellationToken cancellationToken) =>
            ValueTask.FromException<SecurityActivitySlice>(new InvalidOperationException(Message));
    }
}
