using System.Globalization;
using System.Net;
using System.Text;
using AgentShield.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Serilog.Events;

namespace AgentShield.IntegrationTests.Logging;

/// <summary>
/// 401, 403 and 429 leave one structured warning with safe metadata (reason category, endpoint template, client ID)
/// and the request's correlation ID; none contains a presented key, and a rejected request never reaches the analysis.
/// </summary>
public class AccessControlLoggingTests(AgentShieldFactory factory) : IClassFixture<AgentShieldFactory>
{
    private const string Route = "/api/v1/firewall/analyze";
    private const string Endpoint = "api/v1/firewall/analyze";
    private const string NoPermissionKey = "no-permission-key-0123456789abcdefghijklmnop";

    [Fact]
    public async Task Unauthenticated_LogsReasonAndCorrelationId_ButNeverThePresentedKey()
    {
        var presented = "presented-key-" + Guid.NewGuid().ToString("N");

        var response = await SendAsync(factory.CreateClient(), "acl-401-unknown", apiKey: presented);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        var entry = Assert.Single(EventsFor("acl-401-unknown"), IsEvent(2000));
        Assert.Equal(LogEventLevel.Warning, entry.Level);
        Assert.Equal("UnknownKey", Scalar(entry, "AuthFailure"));
        Assert.Equal(Endpoint, Scalar(entry, "Endpoint"));
        Assert.Equal("POST", Scalar(entry, "RequestMethod"));
        Assert.Equal(CorrelationIdOf(response), Scalar(entry, "CorrelationId"));
        AssertNoEventContains(presented);
        AssertNoSecurityEvent("acl-401-unknown");
    }

    [Theory]
    [InlineData("acl-401-short", "too-short-key")]
    [InlineData("acl-401-long", 257)]
    [InlineData("acl-401-chars", "malformed!key-0123456789abcdefghijklmnopqrstu")]
    public async Task MalformedKey_IsLoggedAsMalformed_NotAsUnknown(string correlationId, object key)
    {
        // The response is the same 401 either way; the log tells operators whether a caller sent something that cannot be
        // a key (probing, a broken client) or a well-formed key nobody holds (mutation testing: the categories were never
        // told apart).
        var presented = key as string ?? new string('k', (int)key);

        var response = await SendAsync(factory.CreateClient(), correlationId, apiKey: presented);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("MalformedKey", Scalar(Assert.Single(EventsFor(correlationId), IsEvent(2000)), "AuthFailure"));
        AssertNoEventContains(presented);
    }

    [Fact]
    public async Task MissingKey_IsLoggedAsMissing()
    {
        var response = await SendAsync(factory.CreateClient(), "acl-401-missing", apiKey: null);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Equal("MissingKey", Scalar(Assert.Single(EventsFor("acl-401-missing"), IsEvent(2000)), "AuthFailure"));
    }

    [Fact]
    public async Task Forbidden_LogsClientEndpointAndCorrelationId()
    {
        using var host = factory.WithWebHostBuilder(builder =>
            builder.UseSetting("Authentication:Clients:test-no-permissions:KeyHashes:0", TestApiKeys.Hash(NoPermissionKey)));

        var response = await SendAsync(host.CreateClient(), "acl-403", apiKey: NoPermissionKey);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        var entry = Assert.Single(EventsFor("acl-403"), IsEvent(2001));
        Assert.Equal(LogEventLevel.Warning, entry.Level);
        Assert.Equal("test-no-permissions", Scalar(entry, "ClientId"));
        Assert.Equal(Endpoint, Scalar(entry, "Endpoint"));
        AssertNoEventContains(NoPermissionKey);
        AssertNoSecurityEvent("acl-403");
    }

    [Fact]
    public async Task RateLimited_LogsPolicyEndpointClientAndCorrelationId_AndSkipsTheAnalysis()
    {
        using var host = factory.WithWebHostBuilder(builder => builder.UseSetting("RateLimiting:Firewall:PermitLimit", "1"));
        using var client = host.CreateClient();
        Assert.Equal(HttpStatusCode.OK, (await SendAsync(client, "acl-429-first", TestApiKeys.Analyzer)).StatusCode);

        var response = await SendAsync(client, "acl-429-second", TestApiKeys.Analyzer);

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        var entry = Assert.Single(EventsFor("acl-429-second"), IsEvent(2100));
        Assert.Equal(LogEventLevel.Warning, entry.Level);
        Assert.Equal("Firewall", Scalar(entry, "RateLimitPolicy"));
        Assert.Equal(Endpoint, Scalar(entry, "Endpoint"));
        Assert.Equal(TestApiKeys.AnalyzerClientId, Scalar(entry, "ClientId"));
        Assert.Equal(CorrelationIdOf(response), Scalar(entry, "CorrelationId"));
        Assert.InRange(entry.Timestamp, DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
        AssertNoSecurityEvent("acl-429-second");
    }

    [Fact]
    public async Task AuthenticatedAnalysis_SecurityEventAndRequestLog_CarryTheClientId_ButNotTheKey()
    {
        var response = await SendAsync(factory.CreateClient(), "acl-200-client", TestApiKeys.Analyzer);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var events = EventsFor("acl-200-client").ToList();
        var securityEvent = Assert.Single(events, entry => entry.Properties.ContainsKey("SecurityEventId"));
        Assert.Equal(TestApiKeys.AnalyzerClientId, Scalar(securityEvent, "ClientId"));
        var requestLog = Assert.Single(events, entry => entry.MessageTemplate.Text.StartsWith("HTTP ", StringComparison.Ordinal));
        Assert.Equal(TestApiKeys.AnalyzerClientId, Scalar(requestLog, "ClientId"));
        AssertNoEventContains(TestApiKeys.Analyzer);
    }

    [Fact]
    public async Task DevelopmentKey_AcceptedInDevelopment_NeverReachesALog()
    {
        // The public Development key is a real credential in Development: it is logged no more than any other key.
        const string DevelopmentKey = "agentshield-development-only-key-not-a-secret";

        var accepted = await SendAsync(factory.CreateClient(), "acl-200-development", DevelopmentKey);
        var wrongCase = await SendAsync(factory.CreateClient(), "acl-401-development", DevelopmentKey.ToUpperInvariant());

        Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);
        Assert.Equal("development", Scalar(Assert.Single(EventsFor("acl-200-development"), entry => entry.Properties.ContainsKey("SecurityEventId")), "ClientId"));
        Assert.Equal(HttpStatusCode.Unauthorized, wrongCase.StatusCode);
        AssertNoEventContains(DevelopmentKey);
        AssertNoEventContains(DevelopmentKey.ToUpperInvariant());
    }

    private static async Task<HttpResponseMessage> SendAsync(HttpClient client, string correlationId, string? apiKey)
    {
        client.DefaultRequestHeaders.Remove(TestApiKeys.HeaderName);
        using var request = new HttpRequestMessage(HttpMethod.Post, Route)
        {
            Content = new StringContent("""{"input":"What is the capital of France?"}""", Encoding.UTF8, "application/json"),
        };
        request.Headers.Add("X-Correlation-ID", correlationId);
        if (apiKey is not null)
        {
            request.Headers.Add(TestApiKeys.HeaderName, apiKey);
        }

        return await client.SendAsync(request);
    }

    private IEnumerable<LogEvent> EventsFor(string correlationId) =>
        factory.LogSink.Events.Where(entry => Scalar(entry, "CorrelationId") == correlationId);

    private void AssertNoSecurityEvent(string correlationId) =>
        Assert.DoesNotContain(EventsFor(correlationId), entry => entry.Properties.ContainsKey("SecurityEventId"));

    private void AssertNoEventContains(string secret) =>
        Assert.All(factory.LogSink.Events, entry =>
        {
            var rendered = entry.RenderMessage(CultureInfo.InvariantCulture)
                + string.Concat(entry.Properties.Values.Select(value => value.ToString()))
                + entry.Exception;
            Assert.DoesNotContain(secret, rendered, StringComparison.Ordinal);
        });

    private static Predicate<LogEvent> IsEvent(int eventId) =>
        entry => entry.Properties.TryGetValue("EventId", out var value)
            && value is StructureValue structure
            && structure.Properties.Any(property => property.Name == "Id" && property.Value.ToString() == eventId.ToString(CultureInfo.InvariantCulture));

    private static string CorrelationIdOf(HttpResponseMessage response) =>
        Assert.Single(response.Headers.GetValues("X-Correlation-ID"));

    private static string? Scalar(LogEvent entry, string name) =>
        entry.Properties.TryGetValue(name, out var value) && value is ScalarValue scalar
            ? Convert.ToString(scalar.Value, CultureInfo.InvariantCulture)
            : null;
}
