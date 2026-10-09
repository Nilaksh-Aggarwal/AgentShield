using System.Net;
using AgentShield.ApiTests.Infrastructure;

namespace AgentShield.ApiTests.Auth;

/// <summary>The Development access path does not exist in Production.</summary>
public sealed class ProductionAuthenticationTests : IDisposable
{
    private readonly ProductionApiFactory _production = new();

    [Fact]
    public async Task PublicDevelopmentKey_InProduction_Returns401()
    {
        using var client = AnalyzeRequests.CreateAnonymousClient(_production);

        var response = await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Development));

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
    }

    [Fact]
    public async Task NoCredentials_InProduction_Returns401()
    {
        using var client = AnalyzeRequests.CreateAnonymousClient(_production);

        var response = await client.SendAsync(AnalyzeRequests.Create());

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
    }

    [Fact]
    public async Task ConfiguredClient_InProduction_Returns200()
    {
        using var client = AnalyzeRequests.CreateAnonymousClient(_production);

        var response = await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Production_HealthLiveAndReady_StayAnonymous()
    {
        using var client = AnalyzeRequests.CreateAnonymousClient(_production);

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/live")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/ready")).StatusCode);
    }

    public void Dispose() => _production.Dispose();
}
