using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using AgentShield.ApiTests.Infrastructure;

namespace AgentShield.ApiTests.Http;

public class SuccessResponseContractTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task Ok_ReturnsEnvelopeWithDataAndMeta_AndNoSuccessFlag()
    {
        var response = await _client.GetAsync("/api/v1/__probe/ok");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);

        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = body.RootElement;

        Assert.Equal("p-1", root.GetProperty("data").GetProperty("id").GetString());
        // Enums and domain decisions travel as strings; an HTTP 200 may legitimately carry a BLOCK decision.
        Assert.Equal("Block", root.GetProperty("data").GetProperty("decision").GetString());

        var meta = root.GetProperty("meta");
        Assert.Equal(Assert.Single(response.Headers.GetValues("X-Correlation-ID")), meta.GetProperty("correlationId").GetString());
        Assert.True(meta.TryGetProperty("timestamp", out _));

        Assert.False(root.TryGetProperty("success", out _));
    }

    [Fact]
    public async Task Created_Returns201WithLocationAndEnvelope()
    {
        var response = await _client.PostAsJsonAsync("/api/v1/__probe/created", new { name = "rule", priority = 1 });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        Assert.Equal("/api/v1/__probe/p-2", response.Headers.Location?.OriginalString);

        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal("rule", body.RootElement.GetProperty("data").GetProperty("decision").GetString());
    }

    [Fact]
    public async Task Accepted_Returns202()
    {
        var response = await _client.PostAsync("/api/v1/__probe/accepted", content: null);

        Assert.Equal(HttpStatusCode.Accepted, response.StatusCode);
    }

    [Fact]
    public async Task NoContent_Returns204WithoutBody()
    {
        var response = await _client.DeleteAsync("/api/v1/__probe/no-content");

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Empty(await response.Content.ReadAsByteArrayAsync());
    }
}
