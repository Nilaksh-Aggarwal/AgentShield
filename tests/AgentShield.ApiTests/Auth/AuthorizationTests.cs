using System.Net;
using AgentShield.Api.Auth;
using AgentShield.ApiTests.Infrastructure;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AgentShield.ApiTests.Auth;

/// <summary>Permission policies (403), the secure-by-default fallback policy, and the explicitly anonymous probes.</summary>
public sealed class AuthorizationTests(ApiFactory factory) : IClassFixture<ApiFactory>, IDisposable
{
    private readonly HttpClient _anonymous = AnalyzeRequests.CreateAnonymousClient(factory);

    [Fact]
    public void EndpointInventory_OnlyTheHealthProbesAreAnonymous_AndAnalyzeAndActivityRequireTheirPermissionPolicies()
    {
        // Read from the app's own routing table, so a new [AllowAnonymous] action, or the analyze or activity endpoint
        // losing its permission policy, fails here even if no request test covers that endpoint yet.
        var endpoints = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints.OfType<RouteEndpoint>().ToArray();

        var anonymous = endpoints
            .Where(endpoint => endpoint.Metadata.GetMetadata<IAllowAnonymous>() is not null)
            .Select(endpoint => "/" + endpoint.RoutePattern.RawText!.TrimStart('/'))
            .Order(StringComparer.Ordinal);
        Assert.Equal(["/health", "/health/live", "/health/ready"], anonymous);

        var analyze = Assert.Single(endpoints, endpoint => endpoint.RoutePattern.RawText == "api/v1/firewall/analyze");
        Assert.Contains(
            analyze.Metadata.GetOrderedMetadata<IAuthorizeData>(),
            authorize => authorize.Policy == AuthorizationPolicies.FirewallAnalyze);

        var activity = Assert.Single(endpoints, endpoint => endpoint.RoutePattern.RawText == "api/v1/activity");
        Assert.Equal(
            [AuthorizationPolicies.ActivityRead],
            activity.Metadata.GetOrderedMetadata<IAuthorizeData>().Select(authorize => authorize.Policy).OfType<string>());
    }

    [Fact]
    public async Task Analyze_AuthenticatedClientWithoutPermission_Returns403ProblemDetails()
    {
        var response = await _anonymous.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.NoPermissions));

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Forbidden, "Auth.Forbidden");
        Assert.Empty(response.Headers.WwwAuthenticate);
        Assert.DoesNotContain("firewall:analyze", problem.GetRawText(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Analyze_ClientWithPermission_Returns200()
    {
        var response = await _anonymous.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task EndpointWithoutPolicy_RequiresAuthentication_ButNoPermission()
    {
        // The probe controller declares no policy: the fallback policy (authenticated client) applies.
        var anonymous = await _anonymous.GetAsync("/api/v1/__probe/ok");
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/__probe/ok");
        request.Headers.Add(TestApiKeys.HeaderName, TestApiKeys.NoPermissions);
        var authenticated = await _anonymous.SendAsync(request);

        await ProblemAssertions.AssertProblemAsync(anonymous, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
        Assert.Equal(HttpStatusCode.OK, authenticated.StatusCode);
    }

    [Theory]
    [InlineData("/health/live")]
    [InlineData("/health/ready")]
    [InlineData("/health")]
    public async Task HealthEndpoints_AreAnonymous(string path)
    {
        var response = await _anonymous.GetAsync(path);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task HealthLive_WithInvalidApiKey_StillReturns200()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/health/live");
        request.Headers.Add(TestApiKeys.HeaderName, "invalid-key-0123456789abcdefghijklmnopqrstu");

        var response = await _anonymous.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task UnknownRoute_Anonymous_Returns401_WithoutRevealingWhetherItExists()
    {
        var unknown = await _anonymous.GetAsync("/api/v1/does-not-exist");
        var existing = await _anonymous.GetAsync("/api/v1/__probe/ok");

        await ProblemAssertions.AssertProblemAsync(unknown, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
        Assert.Equal(existing.StatusCode, unknown.StatusCode);
    }

    [Fact]
    public async Task UnknownRoute_Authenticated_Returns404()
    {
        var response = await factory.CreateClient().GetAsync("/api/v1/does-not-exist");

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.NotFound, "Resource.NotFound");
    }

    public void Dispose() => _anonymous.Dispose();
}
