using System.Text;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace AgentShield.ApiTests.Infrastructure;

/// <summary>
/// <see cref="ApiFactory"/> plus the test agents, each bound to <see cref="TestApiKeys.AgentRuntimeClientId"/>. The IDs differ
/// from the Development demo agents (also loaded in Development) so configuration arrays never merge.
/// </summary>
public sealed class AgentApiFactory : ApiFactory
{
    /// <summary>Holds data:read, email:read, email:draft and email:send.</summary>
    public const string SupportAgent = "test-support-agent";

    /// <summary>Holds data:read only.</summary>
    public const string ReaderAgent = "test-reader-agent";

    /// <summary>Holds data:read and payment:execute.</summary>
    public const string FinanceAgent = "test-finance-agent";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        Configure(builder);
    }

    /// <summary>Registers the test agents on a host.</summary>
    public static void Configure(IWebHostBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        Agent(builder, SupportAgent, "data:read", "email:read", "email:draft", "email:send");
        Agent(builder, ReaderAgent, "data:read");
        Agent(builder, FinanceAgent, "data:read", "payment:execute");
    }

    private static void Agent(IWebHostBuilder builder, string id, params string[] capabilities)
    {
        for (var index = 0; index < capabilities.Length; index++)
        {
            builder.UseSetting($"AgentAuthorization:Agents:{id}:Capabilities:{index}", capabilities[index]);
        }

        builder.UseSetting($"AgentAuthorization:Agents:{id}:Clients:0", TestApiKeys.AgentRuntimeClientId);
    }
}

/// <summary>Requests to the agent action authorization endpoint with explicit control over credentials.</summary>
internal static class AgentRequests
{
    public const string Route = "/api/v1/agent/actions/authorize";

    public static HttpRequestMessage Create(string body, string? apiKey = TestApiKeys.AgentRuntime, string? correlationId = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, Route) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (apiKey is not null)
        {
            request.Headers.Add(TestApiKeys.HeaderName, apiKey);
        }

        if (correlationId is not null)
        {
            request.Headers.Add("X-Correlation-ID", correlationId);
        }

        return request;
    }

    public static string Body(string agentId, string tool, string action, string capability, string? inputDecision = null) =>
        inputDecision is null
            ? $$"""{"agentId":"{{agentId}}","tool":"{{tool}}","action":"{{action}}","capability":"{{capability}}"}"""
            : $$"""{"agentId":"{{agentId}}","tool":"{{tool}}","action":"{{action}}","capability":"{{capability}}","inputDecision":"{{inputDecision}}"}""";

    public static async Task<HttpResponseMessage> SendAsync(WebApplicationFactory<Program> host, string body, string? apiKey = TestApiKeys.AgentRuntime, string? correlationId = null)
    {
        using var client = AnalyzeRequests.CreateAnonymousClient(host);
        using var request = Create(body, apiKey, correlationId);
        return await client.SendAsync(request);
    }
}
