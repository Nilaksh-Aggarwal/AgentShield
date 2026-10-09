using System.Net;
using System.Text;
using AgentShield.ApiTests.Infrastructure;

namespace AgentShield.ApiTests.Http;

/// <summary>Hostile or unusual requests at the API boundary: bounded, deterministic, never a 500.</summary>
public sealed class AdversarialRequestTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    [Theory]
    [InlineData("GET")]
    [InlineData("PUT")]
    [InlineData("PATCH")]
    [InlineData("DELETE")]
    [InlineData("TRACE")]
    [InlineData("PROPFIND")]
    public async Task Analyze_WithUnsupportedMethod_Authenticated_Returns405ProblemDetails(string method)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), AnalyzeRequests.Route);

        var response = await factory.CreateClient().SendAsync(request);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.MethodNotAllowed, "Request.MethodNotAllowed");
    }

    [Theory]
    [InlineData("GET")]
    [InlineData("DELETE")]
    [InlineData("TRACE")]
    public async Task Analyze_WithUnsupportedMethod_Anonymous_Returns401_NotTheAllowedMethods(string method)
    {
        using var client = AnalyzeRequests.CreateAnonymousClient(factory);
        using var request = new HttpRequestMessage(new HttpMethod(method), AnalyzeRequests.Route);

        var response = await client.SendAsync(request);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
        Assert.False(response.Content.Headers.Contains("Allow"));
    }

    [Fact]
    public async Task Analyze_OptionsWithoutOrigin_IsNotAPreflight_AndIsNotServedAnonymously()
    {
        using var client = AnalyzeRequests.CreateAnonymousClient(factory);
        using var request = new HttpRequestMessage(HttpMethod.Options, AnalyzeRequests.Route);

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task Analyze_InputOverTheLimit_Authenticated_Returns422_AndTheLimitIsUnchanged()
    {
        var atLimit = await factory.CreateClient().SendAsync(AnalyzeRequests.Create($$"""{"input":"{{new string('a', 32_000)}}"}""", TestApiKeys.Analyzer));
        var overLimit = await factory.CreateClient().SendAsync(AnalyzeRequests.Create($$"""{"input":"{{new string('a', 32_001)}}"}""", TestApiKeys.Analyzer));

        Assert.Equal(HttpStatusCode.OK, atLimit.StatusCode);
        await ProblemAssertions.AssertProblemAsync(overLimit, HttpStatusCode.UnprocessableEntity, "Validation.Failed");
    }

    [Fact]
    public async Task Analyze_OversizedInput_Anonymous_IsRejectedBeforeBodyValidation()
    {
        using var client = AnalyzeRequests.CreateAnonymousClient(factory);

        var response = await client.SendAsync(AnalyzeRequests.Create($$"""{"input":"{{new string('a', 32_001)}}"}"""));

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
    }

    [Fact]
    public async Task Analyze_MalformedJson_Anonymous_Returns401_NotParserDetails()
    {
        using var client = AnalyzeRequests.CreateAnonymousClient(factory);

        var response = await client.SendAsync(AnalyzeRequests.Create("""{"input":"a","input":"b"}"""));

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
    }

    [Fact]
    public async Task Analyze_WithoutContentType_Authenticated_Returns415()
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, AnalyzeRequests.Route)
        {
            Content = new ByteArrayContent(Encoding.UTF8.GetBytes(AnalyzeRequests.CleanBody)),
        };

        var response = await factory.CreateClient().SendAsync(request);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.UnsupportedMediaType, "Request.UnsupportedMediaType");
    }

    [Fact]
    public async Task Analyze_WithSpoofedForwardingHeaders_IsNotTreatedAsAnotherClient()
    {
        // Forwarded headers are not honoured (no trusted proxy configured): they cannot change identity or scheme.
        using var client = AnalyzeRequests.CreateAnonymousClient(factory);
        using var request = AnalyzeRequests.Create();
        request.Headers.Add("X-Forwarded-For", "127.0.0.1");
        request.Headers.Add("X-Forwarded-Proto", "https");
        request.Headers.Add("X-Original-URL", "/health/live");
        request.Headers.Add("X-Rewrite-URL", "/health/live");

        var response = await client.SendAsync(request);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
    }
}
