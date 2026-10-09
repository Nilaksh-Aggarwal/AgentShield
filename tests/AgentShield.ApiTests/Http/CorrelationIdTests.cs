using AgentShield.ApiTests.Infrastructure;

namespace AgentShield.ApiTests.Http;

public class CorrelationIdTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private const string Header = "X-Correlation-ID";
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task WellFormedInboundId_IsEchoed()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/__probe/ok");
        request.Headers.Add(Header, "client-req_42:abc.1");

        var response = await _client.SendAsync(request);

        Assert.Equal("client-req_42:abc.1", Assert.Single(response.Headers.GetValues(Header)));
    }

    [Fact]
    public async Task MissingId_IsGenerated()
    {
        var response = await _client.GetAsync("/api/v1/__probe/ok");

        var id = Assert.Single(response.Headers.GetValues(Header));
        Assert.Matches("^[0-9a-f]{32}$", id);
    }

    [Theory]
    [InlineData("contains spaces")]
    [InlineData("<script>alert(1)</script>")]
    [InlineData("line\\nbreak")]
    public async Task MalformedInboundId_IsReplaced(string malicious)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/__probe/ok");
        request.Headers.TryAddWithoutValidation(Header, malicious);

        var response = await _client.SendAsync(request);

        var id = Assert.Single(response.Headers.GetValues(Header));
        Assert.NotEqual(malicious, id);
        Assert.Matches("^[0-9a-f]{32}$", id);
    }

    [Fact]
    public async Task OverlongInboundId_IsReplaced()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/__probe/ok");
        request.Headers.Add(Header, new string('a', 65));

        var response = await _client.SendAsync(request);

        Assert.Matches("^[0-9a-f]{32}$", Assert.Single(response.Headers.GetValues(Header)));
    }

    [Fact]
    public async Task ErrorResponses_CarryTheHeaderToo()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/__probe/throw");
        request.Headers.Add(Header, "trace-500");

        var response = await _client.SendAsync(request);

        Assert.Equal("trace-500", Assert.Single(response.Headers.GetValues(Header)));
    }
}
