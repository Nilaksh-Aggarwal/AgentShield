using System.Net;
using AgentShield.ApiTests.Infrastructure;
using Microsoft.AspNetCore.Mvc.Testing;

namespace AgentShield.ApiTests.Cors;

/// <summary>
/// CORS is an allow-list: only configured origins receive <c>Access-Control-Allow-Origin</c>. The server still answers
/// a disallowed origin's simple request (CORS is enforced by the browser, not an access control), so these tests assert
/// on the headers the browser relies on.
/// </summary>
public sealed class CorsTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private const string DevelopmentOrigin = "http://localhost:5173";

    private static readonly string[] AllowListedMethods = ["GET", "POST"];

    private static readonly string[] AllowListedHeaders = ["Accept", "Content-Type", "X-Correlation-ID"];

    public static TheoryData<string> UntrustedOrigins => new()
    {
        "https://evil.example",
        "http://localhost:5173.evil.example",
        "http://evil.example/http://localhost:5173",
        "http://localhost:5174",
        "https://localhost:5173",
        "http://127.0.0.1:5173",
        "null",
        "*",
        "file://",
    };

    [Fact]
    public async Task Preflight_FromDevelopmentOrigin_InDevelopment_IsAllowedWithoutCredentials()
    {
        var response = await PreflightAsync(factory, DevelopmentOrigin);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal(DevelopmentOrigin, Single(response, "Access-Control-Allow-Origin"));
        Assert.Contains("POST", Single(response, "Access-Control-Allow-Methods"), StringComparison.Ordinal);
        Assert.Equal("600", Single(response, "Access-Control-Max-Age"));
        Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));
    }

    [Theory]
    [MemberData(nameof(UntrustedOrigins))]
    public async Task Preflight_FromUntrustedOrSpoofedOrigin_IsNotAllowed(string origin)
    {
        var response = await PreflightAsync(factory, origin);

        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
        Assert.False(response.Headers.Contains("Access-Control-Allow-Methods"));
    }

    [Theory]
    [InlineData("DELETE", "content-type")]
    [InlineData("PUT", "content-type")]
    [InlineData("POST", "x-api-key")]
    [InlineData("POST", "authorization")]
    [InlineData("POST", "x-custom-header")]
    public async Task Preflight_ForMethodOrHeaderOutsideTheAllowList_IsNotAllowed(string method, string header)
    {
        // The origin is allowed, so the preflight names it; the browser then blocks the request because the requested
        // method or header is missing from the allow lists.
        var response = await PreflightAsync(factory, DevelopmentOrigin, method, header);

        var allowedMethods = List(response, "Access-Control-Allow-Methods");
        var allowedHeaders = List(response, "Access-Control-Allow-Headers");
        Assert.False(
            allowedMethods.Contains(method, StringComparer.OrdinalIgnoreCase) && allowedHeaders.Contains(header, StringComparer.OrdinalIgnoreCase),
            $"Preflight allowed {method} with {header}.");
        Assert.All(allowedMethods, allowed => Assert.Contains(allowed, AllowListedMethods));
        Assert.All(allowedHeaders, allowed => Assert.Contains(allowed, AllowListedHeaders, StringComparer.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ActualRequest_FromAllowedOrigin_ExposesCorrelationAndRetryHeaders()
    {
        using var request = AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer);
        request.Headers.Add("Origin", DevelopmentOrigin);

        var response = await factory.CreateClient().SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(DevelopmentOrigin, Single(response, "Access-Control-Allow-Origin"));
        var exposed = Single(response, "Access-Control-Expose-Headers");
        Assert.Contains("X-Correlation-ID", exposed, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Retry-After", exposed, StringComparison.OrdinalIgnoreCase);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Credentials"));
    }

    [Fact]
    public async Task ActualRequest_FromUntrustedOrigin_GetsNoCorsHeaders()
    {
        using var request = AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer);
        request.Headers.Add("Origin", "https://evil.example");

        var response = await factory.CreateClient().SendAsync(request);

        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
        Assert.False(response.Headers.Contains("Access-Control-Expose-Headers"));
    }

    [Fact]
    public async Task Preflight_IsNotChallengedForCredentials()
    {
        var response = await PreflightAsync(factory, DevelopmentOrigin);

        Assert.NotEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Empty(response.Headers.WwwAuthenticate);
    }

    [Fact]
    public async Task Production_ConfiguredOrigin_IsAllowed()
    {
        await using var production = new ProductionApiFactory();

        var response = await PreflightAsync(production, ProductionApiFactory.AllowedOrigin);

        Assert.Equal(ProductionApiFactory.AllowedOrigin, Single(response, "Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task Production_DevelopmentOrigin_IsNotAllowed()
    {
        await using var production = new ProductionApiFactory();

        var response = await PreflightAsync(production, DevelopmentOrigin);

        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task Production_WithoutConfiguredOrigins_AllowsNoOrigin()
    {
        await using var withoutOrigins = new ProductionApiFactory(configureOrigin: false);

        var allowed = await PreflightAsync(withoutOrigins, ProductionApiFactory.AllowedOrigin);

        Assert.False(allowed.Headers.Contains("Access-Control-Allow-Origin"));
    }

    private static async Task<HttpResponseMessage> PreflightAsync(
        WebApplicationFactory<Program> host, string origin, string method = "POST", string headers = "content-type,x-correlation-id")
    {
        using var request = new HttpRequestMessage(HttpMethod.Options, AnalyzeRequests.Route);
        request.Headers.TryAddWithoutValidation("Origin", origin);
        request.Headers.Add("Access-Control-Request-Method", method);
        request.Headers.Add("Access-Control-Request-Headers", headers);
        using var client = AnalyzeRequests.CreateAnonymousClient(host);
        return await client.SendAsync(request);
    }

    private static string Single(HttpResponseMessage response, string header) =>
        Assert.Single(response.Headers.GetValues(header));

    private static string[] List(HttpResponseMessage response, string header) =>
        response.Headers.TryGetValues(header, out var values)
            ? [.. values.SelectMany(value => value.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))]
            : [];
}
