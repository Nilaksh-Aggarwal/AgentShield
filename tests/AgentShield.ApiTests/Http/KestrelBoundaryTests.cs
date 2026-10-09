using System.Net;
using AgentShield.ApiTests.Infrastructure;
using Microsoft.AspNetCore.Mvc.Testing;

namespace AgentShield.ApiTests.Http;

/// <summary>
/// Behaviour only the real server shows (the in-memory TestServer neither adds a Server header nor enforces header
/// limits): the API on a real Kestrel listener (loopback, dynamic port).
/// </summary>
public sealed class KestrelBoundaryTests : IDisposable
{
    private readonly ApiFactory _factory = new();
    private readonly HttpClient _client;

    public KestrelBoundaryTests()
    {
        _factory.UseKestrel(0);
        _factory.StartServer();
        _client = _factory.CreateClient();
    }

    [Fact]
    public async Task Responses_CarryNoServerBanner()
    {
        var success = await _client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));
        var error = await _client.GetAsync("/api/v1/does-not-exist");

        Assert.Equal(HttpStatusCode.OK, success.StatusCode);
        Assert.Empty(success.Headers.Server);
        Assert.Empty(error.Headers.Server);
    }

    [Fact]
    public async Task ExtremelyLongHeader_IsRejectedByTheServer_BeforeTheApplication()
    {
        // Kestrel's default total header limit is 32 KiB; the request never reaches authentication or the firewall.
        using var request = AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer);
        request.Headers.TryAddWithoutValidation("X-Padding", new string('a', 64 * 1024));

        var response = await _client.SendAsync(request);

        Assert.Equal(HttpStatusCode.RequestHeaderFieldsTooLarge, response.StatusCode);
    }

    [Fact]
    public async Task LongApiKeyWithinServerLimits_Returns401_NotAServerError()
    {
        var response = await _client.SendAsync(AnalyzeRequests.Create(apiKeys: new string('k', 16 * 1024)));

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
    }

    public void Dispose()
    {
        _client.Dispose();
        _factory.Dispose();
    }
}
