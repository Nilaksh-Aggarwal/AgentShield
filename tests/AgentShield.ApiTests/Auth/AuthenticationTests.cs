using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using AgentShield.Api.Auth;
using AgentShield.ApiTests.Infrastructure;
using Microsoft.AspNetCore.Hosting;

namespace AgentShield.ApiTests.Auth;

/// <summary>API key authentication of the firewall endpoint: 401 for every kind of bad credential, 200 for a good one.</summary>
public sealed class AuthenticationTests(ApiFactory factory) : IClassFixture<ApiFactory>, IDisposable
{
    private readonly HttpClient _client = AnalyzeRequests.CreateAnonymousClient(factory);

    public static TheoryData<string> MalformedKeys => new()
    {
        string.Empty,
        "too-short",
        new string('k', 257),
        new string('k', 8 * 1024),
        "test-analyzer-key 0123456789abcdefghijklmnop",
        "test-analyzer-key-0123456789abcdefghijklmnop, test-analyzer-key-0123456789abcdefghijklmnop",
        "c29tZS1iYXNlNjQrd2l0aC9zbGFzaGVzK2FuZC1wYWRkaW5nPQ==",
        "Bearer test-analyzer-key-0123456789abcdefghijklmnop",
        "' OR '1'='1' -- 0123456789abcdefghijklmnopqrstuv",
        "../../../../etc/passwd/0123456789abcdefghijklmnop",
    };

    [Fact]
    public async Task Analyze_WithoutApiKey_Returns401ProblemDetailsWithChallenge()
    {
        var response = await _client.SendAsync(AnalyzeRequests.Create());

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
        Assert.Equal("ApiKey", Assert.Single(response.Headers.WwwAuthenticate).Scheme);
        Assert.False(problem.TryGetProperty("errors", out _));
    }

    [Fact]
    public async Task Analyze_WithUnknownButWellFormedApiKey_Returns401()
    {
        var response = await _client.SendAsync(AnalyzeRequests.Create(apiKeys: "unknown-client-key-0123456789abcdefghijklmn"));

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
    }

    [Theory]
    [MemberData(nameof(MalformedKeys))]
    public async Task Analyze_WithMalformedApiKey_Returns401(string key)
    {
        var response = await _client.SendAsync(AnalyzeRequests.Create(apiKeys: key));

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
    }

    [Fact]
    public async Task Analyze_WithValidApiKey_Returns200()
    {
        var response = await _client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Theory]
    [InlineData(ApiKeys.MinKeyLength, HttpStatusCode.OK)]
    [InlineData(ApiKeys.MaxKeyLength, HttpStatusCode.OK)]
    [InlineData(ApiKeys.MinKeyLength - 1, HttpStatusCode.Unauthorized)]
    [InlineData(ApiKeys.MaxKeyLength + 1, HttpStatusCode.Unauthorized)]
    public async Task Analyze_ConfiguredKeyAtTheLengthLimits_IsAcceptedOnlyWithinThem(int length, HttpStatusCode expected)
    {
        // Both length limits are inclusive, and a configured key one character outside them is never accepted (mutation
        // testing: only keys well inside the limits were used before).
        var key = new string('k', length);
        using var host = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Authentication:Clients:length-test:KeyHashes:0", TestApiKeys.Hash(key));
            builder.UseSetting("Authentication:Clients:length-test:Permissions:0", "firewall:analyze");
        });
        using var client = AnalyzeRequests.CreateAnonymousClient(host);

        var response = await client.SendAsync(AnalyzeRequests.Create(apiKeys: key));

        Assert.Equal(expected, response.StatusCode);
    }

    [Fact]
    public async Task Analyze_WithPublicDevelopmentKey_InDevelopment_Returns200()
    {
        var response = await _client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Development));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Analyze_WithValidKeyInDifferentCase_Returns401()
    {
        var response = await _client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer.ToUpperInvariant()));

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task Analyze_WithTwoApiKeyHeaders_Returns401_EvenIfBothAreValid()
    {
        var response = await _client.SendAsync(AnalyzeRequests.Create(apiKeys: [TestApiKeys.Analyzer, TestApiKeys.Analyzer]));

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
    }

    [Theory]
    [InlineData("Bearer", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.")]
    [InlineData("Bearer", "test-analyzer-key-0123456789abcdefghijklmnop")]
    [InlineData("Bearer", "not a token at all")]
    [InlineData("Basic", "YWRtaW46YWRtaW4=")]
    [InlineData("ApiKey", "test-analyzer-key-0123456789abcdefghijklmnop")]
    public async Task Analyze_WithAuthorizationHeaderInsteadOfApiKey_Returns401(string scheme, string parameter)
    {
        using var request = AnalyzeRequests.Create();
        request.Headers.Authorization = new AuthenticationHeaderValue(scheme, parameter);

        var response = await _client.SendAsync(request);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
    }

    [Fact]
    public async Task Analyze_WithMalformedAuthorizationHeader_Returns401()
    {
        using var request = AnalyzeRequests.Create();
        request.Headers.TryAddWithoutValidation("Authorization", "Bearer");

        var response = await _client.SendAsync(request);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Unauthorized, "Auth.Unauthenticated");
    }

    [Fact]
    public async Task Unauthorized_MissingAndInvalidKey_AreIndistinguishable()
    {
        var missing = await ReadProblemAsync(await _client.SendAsync(AnalyzeRequests.Create()));
        var unknown = await ReadProblemAsync(await _client.SendAsync(AnalyzeRequests.Create(apiKeys: "unknown-client-key-0123456789abcdefghijklmn")));
        var malformed = await ReadProblemAsync(await _client.SendAsync(AnalyzeRequests.Create(apiKeys: "short")));

        Assert.Equal(missing, unknown);
        Assert.Equal(missing, malformed);
    }

    [Fact]
    public async Task Unauthorized_NeverEchoesThePresentedKeyOrAuthenticationInternals()
    {
        const string presented = "leaky-key-that-must-not-come-back-0123456789";

        var response = await _client.SendAsync(AnalyzeRequests.Create(apiKeys: presented));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.DoesNotContain(presented, body, StringComparison.Ordinal);
        Assert.DoesNotContain(presented, string.Join('\n', response.Headers.SelectMany(header => header.Value)), StringComparison.Ordinal);
        foreach (var internalTerm in new[] { "UnknownKey", "MalformedKey", "hash", "Handler", "AgentShield.Api", "client" })
        {
            Assert.DoesNotContain(internalTerm, body, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task RepeatedUnauthorizedRequests_AllFail_AndDoNotLockOutTheValidClient()
    {
        for (var attempt = 0; attempt < 25; attempt++)
        {
            var guess = await _client.SendAsync(AnalyzeRequests.Create(apiKeys: $"guessed-key-{attempt:D4}-0123456789abcdefghijklmnop"));
            Assert.Equal(HttpStatusCode.Unauthorized, guess.StatusCode);
        }

        var legitimate = await _client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));

        Assert.Equal(HttpStatusCode.OK, legitimate.StatusCode);
    }

    public void Dispose() => _client.Dispose();

    // The problem without the per-request members (correlationId, timestamp, traceId).
    private static async Task<string> ReadProblemAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var stable = document.RootElement.EnumerateObject()
            .Where(property => property.Name is not ("correlationId" or "timestamp" or "traceId"))
            .Select(property => $"{property.Name}={property.Value.GetRawText()}");
        return string.Join('|', stable) + $"|status={(int)response.StatusCode}";
    }
}
