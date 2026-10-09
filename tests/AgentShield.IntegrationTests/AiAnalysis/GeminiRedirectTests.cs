using System.Collections.Concurrent;
using System.Net;
using System.Text;
using AgentShield.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace AgentShield.IntegrationTests.AiAnalysis;

/// <summary>
/// The Gemini typed client's real HTTP handler (production composition, no fake transport) against a local server on
/// the loopback interface. Nothing is sent to Google: the request goes to the local server only, with a fake key.
/// </summary>
public class GeminiRedirectTests(AgentShieldFactory factory) : IClassFixture<AgentShieldFactory>
{
    /// <summary>The name <c>AddHttpClient&lt;IAiSecurityAnalyzer, GeminiSecurityAnalyzer&gt;</c> gives the typed client.</summary>
    private const string GeminiClientName = "IAiSecurityAnalyzer";

    private const string KeyHeader = "x-goog-api-key";
    private const string Key = "zq7key-redirect-test-not-a-real-key";

    [Fact]
    public async Task GeminiHttpClient_DoesNotFollowRedirects_SoTheKeyHeaderNeverReachesAnotherHost()
    {
        // Regression (H-03): the typed client followed redirects, and .NET sends custom headers such as x-goog-api-key
        // again on a redirect (it drops only Authorization), so a redirect from the provider endpoint would hand the key
        // to whatever host it named. Pinning the endpoint covers the first request only.
        var received = new ConcurrentQueue<(string Host, string Path, string Key)>();
        var port = 0;
        var builder = WebApplication.CreateEmptyBuilder(new WebApplicationOptions());
        builder.WebHost.UseKestrelCore().UseUrls("http://127.0.0.1:0");
        await using var server = builder.Build();
        server.Run(context =>
        {
            received.Enqueue((context.Request.Host.Host, context.Request.Path.Value ?? string.Empty, context.Request.Headers[KeyHeader].ToString()));
            if (context.Request.Path == "/v1beta/models/gemini:generateContent")
            {
                context.Response.StatusCode = StatusCodes.Status307TemporaryRedirect;
                context.Response.Headers.Location = $"http://localhost:{port}/collect";
            }

            return Task.CompletedTask;
        });
        await server.StartAsync();
        port = new Uri(server.Urls.Single()).Port;

        using var app = factory.WithWebHostBuilder(host =>
        {
            host.UseSetting("Ai:Enabled", "true");
            host.UseSetting("Ai:Gemini:ApiKey", Key);
        });
        using var client = new HttpClient(app.Services.GetRequiredService<IHttpMessageHandlerFactory>().CreateHandler(GeminiClientName), disposeHandler: true);
        using var request = new HttpRequestMessage(HttpMethod.Post, $"http://127.0.0.1:{port}/v1beta/models/gemini:generateContent")
        {
            Content = new StringContent("{}", Encoding.UTF8, "application/json"),
        };
        request.Headers.Add(KeyHeader, Key);

        using var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.TemporaryRedirect, response.StatusCode);
        var only = Assert.Single(received);
        Assert.Equal(("127.0.0.1", "/v1beta/models/gemini:generateContent"), (only.Host, only.Path));
    }
}
