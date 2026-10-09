using System.Globalization;
using System.Net;
using System.Text;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Domain.Threats;
using AgentShield.IntegrationTests.Infrastructure;
using AgentShield.Security.Redaction;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Serilog.Events;

namespace AgentShield.IntegrationTests.Logging;

public class LoggingPipelineTests(AgentShieldFactory factory) : IClassFixture<AgentShieldFactory>
{
    private const string RequestLogSource = "\"Serilog.AspNetCore.RequestLoggingMiddleware\"";

    [Fact]
    public async Task RequestLog_CarriesTheRequestCorrelationId_AndTheRouteNotThePath()
    {
        using var client = factory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/unknown-route-for-logging");
        request.Headers.Add("X-Correlation-ID", "log-correlation-1");

        await client.SendAsync(request);

        var requestLog = RequestLog("log-correlation-1");
        Assert.Equal("\"(unmatched)\"", requestLog.Properties["Endpoint"].ToString());
        Assert.False(requestLog.Properties.ContainsKey("RequestPath"));
        Assert.Equal(LogEventLevel.Information, requestLog.Level);
    }

    [Fact]
    public async Task CallerControlledPathAndQuery_NeverReachTheLogs_OnlyTheRouteTemplateDoes()
    {
        // Regression (H-04): the request log and the exception handler recorded the raw request path, which the caller
        // chooses, also without a key. A path or query can carry anything (a key, an attack, a forged log line).
        var marker = "zq7path" + Guid.NewGuid().ToString("N");
        using var authenticated = factory.CreateClient();
        using var anonymous = factory.CreateClient();
        anonymous.DefaultRequestHeaders.Remove(TestApiKeys.HeaderName);

        await SendAsync(authenticated, HttpMethod.Get, $"/api/v1/{marker}/AIzaSyFakeKeyForAgentShieldTests0000000", "path-unmatched");
        await SendAsync(anonymous, HttpMethod.Get, $"/api/v1/firewall/{marker}%0AForged%20log%20line", "path-anonymous");
        var analysed = await SendAsync(authenticated, HttpMethod.Post, $"/api/v1/firewall/analyze?apiKey={marker}", "path-query", """{"input":"hello"}""");

        Assert.Equal(HttpStatusCode.OK, analysed);
        Assert.All(factory.LogSink.Events, entry => Assert.DoesNotContain(marker, AllText(entry), StringComparison.Ordinal));
        Assert.Equal("\"(unmatched)\"", RequestLog("path-unmatched").Properties["Endpoint"].ToString());
        Assert.Equal("\"(unmatched)\"", RequestLog("path-anonymous").Properties["Endpoint"].ToString());
        Assert.Equal("\"api/v1/firewall/analyze\"", RequestLog("path-query").Properties["Endpoint"].ToString());
    }

    [Fact]
    public async Task UnhandledException_IsLoggedWithTypeMessageAndStack_ButSecretsInItsTextAreMasked()
    {
        // H-01: the redaction enricher sees properties, never exception objects, so an exception message that carried a
        // secret reached the sinks as it was. The handler now logs the exception as text that passes the redactor.
        using var failing = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.AddSingleton<IThreatDetector, SecretLeakingDetector>()));
        using var client = failing.CreateClient();

        var status = await SendAsync(client, HttpMethod.Post, "/api/v1/firewall/analyze", "exception-redaction-1", """{"input":"hello"}""");

        Assert.Equal(HttpStatusCode.InternalServerError, status);
        Assert.All(factory.LogSink.Events, entry =>
        {
            Assert.DoesNotContain(SecretLeakingDetector.Password, AllText(entry), StringComparison.Ordinal);
            Assert.DoesNotContain(SecretLeakingDetector.ApiKey, AllText(entry), StringComparison.Ordinal);
        });

        var error = Assert.Single(factory.LogSink.Events, entry =>
            entry.Properties.ContainsKey("ExceptionDetail")
            && entry.Properties.TryGetValue("CorrelationId", out var id) && id.ToString() == "\"exception-redaction-1\"");
        Assert.Equal(LogEventLevel.Error, error.Level);
        var detail = error.Properties["ExceptionDetail"].ToString();
        Assert.Contains(typeof(InvalidOperationException).FullName!, detail, StringComparison.Ordinal);
        Assert.Contains("Detector failure while reading the rule store", detail, StringComparison.Ordinal);
        Assert.Contains(nameof(SecretLeakingDetector), detail, StringComparison.Ordinal);
        Assert.Contains(SensitiveDataRedactor.Mask, detail, StringComparison.Ordinal);
        Assert.Equal("\"api/v1/firewall/analyze\"", error.Properties["Endpoint"].ToString());
    }

    [Fact]
    public void SensitiveProperties_AreRedactedBeforeReachingSinks()
    {
        using var client = factory.CreateClient();
        var logger = factory.Services.GetRequiredService<ILoggerFactory>().CreateLogger("RedactionProbe");
        var marker = Guid.NewGuid().ToString("N");

#pragma warning disable CA1848, CA1873 // test deliberately logs through the plain API
        logger.LogInformation(
            "Probe {Marker} {ApiKey} {Note} {@Login}",
            marker,
            "sk-live-should-never-appear-0000000000",
            "header was Bearer abc.def.ghi",
            new { Username = "alice", Password = "hunter2" });
#pragma warning restore CA1848, CA1873

        var logEvent = Assert.Single(
            factory.LogSink.Events,
            e => e.Properties.TryGetValue("Marker", out var value) && value.ToString() == $"\"{marker}\"");
        var rendered = logEvent.RenderMessage(System.Globalization.CultureInfo.InvariantCulture);

        Assert.DoesNotContain("sk-live-should-never-appear", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("abc.def.ghi", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("hunter2", rendered, StringComparison.Ordinal);
        Assert.Contains("alice", rendered, StringComparison.Ordinal);
        Assert.Contains(SensitiveDataRedactor.Mask, rendered, StringComparison.Ordinal);
    }

    private LogEvent RequestLog(string correlationId) => Assert.Single(
        factory.LogSink.Events,
        entry => entry.Properties.TryGetValue("SourceContext", out var source) && source.ToString() == RequestLogSource
            && entry.Properties.TryGetValue("CorrelationId", out var id) && id.ToString() == $"\"{correlationId}\"");

    private static string AllText(LogEvent entry) =>
        entry.RenderMessage(CultureInfo.InvariantCulture)
        + string.Concat(entry.Properties.Values.Select(value => value.ToString()))
        + entry.Exception;

    private static async Task<HttpStatusCode> SendAsync(HttpClient client, HttpMethod method, string uri, string correlationId, string? json = null)
    {
        using var request = new HttpRequestMessage(method, uri);
        request.Headers.Add("X-Correlation-ID", correlationId);
        if (json is not null)
        {
            request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        }

        using var response = await client.SendAsync(request);
        return response.StatusCode;
    }

    /// <summary>A detector whose fault message carries secrets (as a careless message in AgentShield's own code could).</summary>
    private sealed class SecretLeakingDetector : IThreatDetector
    {
        public const string Password = "zq7hunter2-not-for-logs";
        public const string ApiKey = "sk-zq7abcdefghijklmnopqrstuv";

        public IReadOnlyList<ThreatFinding> Detect(NormalizedInput input) =>
            throw new InvalidOperationException($"Detector failure while reading the rule store: password={Password}; key {ApiKey}");
    }
}
