using System.Text;
using Microsoft.AspNetCore.Mvc.Testing;

namespace AgentShield.ApiTests.Infrastructure;

/// <summary>Requests to the firewall endpoint with explicit control over credentials.</summary>
internal static class AnalyzeRequests
{
    public const string Route = "/api/v1/firewall/analyze";

    public const string CleanBody = """{"input":"What is the capital of France?"}""";

    /// <summary>A client without the default API key header.</summary>
    public static HttpClient CreateAnonymousClient(WebApplicationFactory<Program> factory)
    {
        ArgumentNullException.ThrowIfNull(factory);
        var client = factory.CreateClient();
        client.DefaultRequestHeaders.Remove(TestApiKeys.HeaderName);
        return client;
    }

    /// <summary>A POST to the analyze endpoint carrying exactly the given <c>X-API-Key</c> values (none if empty).</summary>
    public static HttpRequestMessage Create(string body = CleanBody, params string[] apiKeys)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, Route)
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        foreach (var key in apiKeys)
        {
            request.Headers.TryAddWithoutValidation(TestApiKeys.HeaderName, key);
        }

        return request;
    }
}
