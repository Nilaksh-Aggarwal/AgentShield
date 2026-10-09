using System.Net;
using AgentShield.ApiTests.Infrastructure;

namespace AgentShield.ApiTests.Http;

/// <summary>Security response headers on successes and on every kind of error, and no technology disclosure.</summary>
public sealed class SecurityHeadersTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    public static TheoryData<string, string, string?, HttpStatusCode> Responses => new()
    {
        { "POST", AnalyzeRequests.Route, TestApiKeys.Analyzer, HttpStatusCode.OK },
        { "POST", AnalyzeRequests.Route, null, HttpStatusCode.Unauthorized },
        { "POST", AnalyzeRequests.Route, TestApiKeys.NoPermissions, HttpStatusCode.Forbidden },
        { "GET", "/api/v1/does-not-exist", TestApiKeys.Analyzer, HttpStatusCode.NotFound },
        { "GET", "/api/v1/__probe/failure/Validation", TestApiKeys.Analyzer, HttpStatusCode.UnprocessableEntity },
        { "GET", "/api/v1/__probe/throw", TestApiKeys.Analyzer, HttpStatusCode.InternalServerError },
        { "GET", "/health/live", null, HttpStatusCode.OK },
        { "GET", "/health/ready", null, HttpStatusCode.OK },
    };

    [Theory]
    [MemberData(nameof(Responses))]
    public async Task EveryApiResponse_CarriesTheSecurityHeaders(string method, string path, string? apiKey, HttpStatusCode expected)
    {
        var response = await SendAsync(method, path, apiKey);

        Assert.Equal(expected, response.StatusCode);
        Assert.Equal("nosniff", Single(response, "X-Content-Type-Options"));
        Assert.Equal("default-src 'none'; frame-ancestors 'none'", Single(response, "Content-Security-Policy"));
        Assert.Equal("DENY", Single(response, "X-Frame-Options"));
        Assert.True(response.Headers.CacheControl?.NoStore);
    }

    [Theory]
    [MemberData(nameof(Responses))]
    public async Task NoResponse_DisclosesServerOrFrameworkTechnology(string method, string path, string? apiKey, HttpStatusCode expected)
    {
        var response = await SendAsync(method, path, apiKey);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(expected, response.StatusCode);
        foreach (var header in new[] { "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-SourceFiles" })
        {
            Assert.False(response.Headers.Contains(header), $"{header} header disclosed");
        }

        foreach (var term in new[] { "Kestrel", "ASP.NET", "Microsoft.", "System.", "Exception", "   at " })
        {
            Assert.DoesNotContain(term, body, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task SwaggerUi_InDevelopment_KeepsNosniff_ButNotTheApiOnlyPolicy()
    {
        var response = await factory.CreateClient().GetAsync("/swagger/index.html");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
        Assert.Equal("nosniff", Single(response, "X-Content-Type-Options"));
        Assert.False(response.Headers.Contains("Content-Security-Policy"));
        Assert.False(response.Headers.Contains("X-Frame-Options"));
    }

    [Fact]
    public async Task Production_SwaggerPath_IsNotServed_AndGetsTheApiPolicy()
    {
        await using var production = new ProductionApiFactory();

        var response = await production.CreateClient().GetAsync("/swagger/index.html");

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("default-src 'none'; frame-ancestors 'none'", Single(response, "Content-Security-Policy"));
    }

    private async Task<HttpResponseMessage> SendAsync(string method, string path, string? apiKey)
    {
        using var client = AnalyzeRequests.CreateAnonymousClient(factory);
        using var request = method == "POST"
            ? AnalyzeRequests.Create(apiKeys: apiKey is null ? [] : [apiKey])
            : new HttpRequestMessage(new HttpMethod(method), path);
        if (method != "POST" && apiKey is not null)
        {
            request.Headers.Add(TestApiKeys.HeaderName, apiKey);
        }

        return await client.SendAsync(request);
    }

    private static string Single(HttpResponseMessage response, string header) =>
        Assert.Single(response.Headers.GetValues(header));
}
