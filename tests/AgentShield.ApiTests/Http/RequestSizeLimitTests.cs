using System.Net;
using System.Text;
using AgentShield.ApiTests.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;

namespace AgentShield.ApiTests.Http;

/// <summary>
/// The body limit is enforced by Kestrel, which the in-memory TestServer does not emulate, so these tests
/// run the API on a real Kestrel listener (loopback, dynamic port) with a small configured limit.
/// </summary>
public sealed class RequestSizeLimitTests : IDisposable
{
    private const int LimitBytes = 1024;

    private readonly ApiFactory _root = new();
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public RequestSizeLimitTests()
    {
        _factory = _root.WithWebHostBuilder(builder =>
            builder.UseSetting("Api:MaxRequestBodySizeBytes", LimitBytes.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        _factory.UseKestrel(0);
        _factory.StartServer();
        _client = _factory.CreateClient();
    }

    [Fact]
    public async Task BodyLargerThanConfiguredLimit_Returns413ProblemDetails()
    {
        var response = await PostEchoAsync(inputLength: LimitBytes * 2);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.RequestEntityTooLarge, "Request.TooLarge");
    }

    [Fact]
    public async Task BodyWithinConfiguredLimit_IsProcessed()
    {
        var response = await PostEchoAsync(inputLength: LimitBytes / 2);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    public void Dispose()
    {
        _client.Dispose();
        _root.Dispose();
    }

    private async Task<HttpResponseMessage> PostEchoAsync(int inputLength)
    {
        using var content = new StringContent($$"""{"input":"{{new string('a', inputLength)}}"}""", Encoding.UTF8, "application/json");
        return await _client.PostAsync("/api/v1/__probe/echo", content);
    }
}
