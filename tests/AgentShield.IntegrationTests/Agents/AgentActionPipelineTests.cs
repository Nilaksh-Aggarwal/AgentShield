using System.Net;
using System.Text;
using System.Text.Json;
using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Activity;
using AgentShield.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Serilog.Events;

namespace AgentShield.IntegrationTests.Agents;

/// <summary>
/// The agent action authorization boundary as the real composition root wires it: the committed Development agents, the
/// audit log, the activity history, fail-closed recording and startup validation of the agent configuration.
/// </summary>
public sealed class AgentActionPipelineTests(AgentShieldFactory factory) : IClassFixture<AgentShieldFactory>
{
    private const string Route = "/api/v1/agent/actions/authorize";

    /// <summary>The public Development key (appsettings.Development.json); its client is bound to the demo agents.</summary>
    private const string DevelopmentKey = "agentshield-development-only-key-not-a-secret";

    [Fact]
    public void Composition_RegistersOneBoundaryCatalogueAndDirectory_AndBothSinks()
    {
        using var client = factory.CreateClient();
        using var scope = factory.Services.CreateScope();
        var services = scope.ServiceProvider;

        Assert.Equal("AgentActionAuthorizer", services.GetRequiredService<IAgentActionAuthorizer>().GetType().Name);
        Assert.Equal("ReferenceToolCatalog", services.GetRequiredService<IToolCatalog>().GetType().Name);
        Assert.Equal("ConfiguredAgentDirectory", services.GetRequiredService<IAgentDirectory>().GetType().Name);
        Assert.Single(services.GetServices<IAgentActionAuthorizer>());
        Assert.Equal(
            ["AgentActionActivityRecorder", "LoggingAgentActionEventSink"],
            services.GetServices<IAgentActionEventSink>().Select(sink => sink.GetType().Name).Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("support-agent", "email", "read", "email:read", "Allow", "Permitted")]
    [InlineData("support-agent", "email", "draft", "email:draft", "Allow", "Permitted")]
    [InlineData("support-agent", "email", "send", "email:send", "Review", "HumanApprovalRequired")]
    [InlineData("research-agent", "data", "read", "data:read", "Allow", "Permitted")]
    [InlineData("research-agent", "email", "send", "email:send", "Block", "CapabilityNotGranted")]
    [InlineData("research-agent", "data", "write", "data:read", "Block", "CapabilityMismatch")]
    [InlineData("operations-agent", "data", "write", "data:write", "Allow", "Permitted")]
    [InlineData("finance-agent", "payment", "execute", "payment:execute", "Block", "CriticalActionDenied")]
    [InlineData("support-agent", "shell", "exec", "shell:exec", "Block", "UnknownTool")]
    public async Task CommittedDevelopmentAgents_AreDecidedAsTheConsolePreviewExpects(string agent, string tool, string action, string capability, string decision, string reason)
    {
        // The frontend's agent authorization preview sends these requests with the Development key.
        var data = await AuthorizeAsync(factory, $$"""{"agentId":"{{agent}}","tool":"{{tool}}","action":"{{action}}","capability":"{{capability}}"}""", DevelopmentKey);

        Assert.Equal((decision, reason), (data.GetProperty("decision").GetString(), data.GetProperty("reason").GetString()));
    }

    [Fact]
    public async Task AuditLog_RecordsEveryDecision_WithRecognisedNamesAndTheClient_ButNeverAMadeUpName()
    {
        using var host = factory.WithWebHostBuilder(_ => { });
        var marker = "zq7audit" + Guid.NewGuid().ToString("N")[..8];

        await AuthorizeAsync(host, """{"agentId":"support-agent","tool":"email","action":"send","capability":"email:send","inputDecision":"Allow"}""", DevelopmentKey, "agent-audit-known");
        await AuthorizeAsync(host, $$"""{"agentId":"{{marker}}","tool":"{{marker}}-tool","action":"exec","capability":"{{marker}}:run"}""", DevelopmentKey, "agent-audit-unknown");

        var entries = factory.LogSink.Events.Where(entry => entry.Properties.ContainsKey("AgentActionReason")).ToArray();
        var known = Assert.Single(entries, entry => Scalar(entry, "CorrelationId") == "agent-audit-known");
        Assert.Equal(LogEventLevel.Warning, known.Level);
        Assert.Equal(("Review", "HumanApprovalRequired", "High"), (Scalar(known, "Decision"), Scalar(known, "AgentActionReason"), Scalar(known, "RiskLevel")));
        Assert.Equal(("support-agent", "email", "send", "email:send"), (Scalar(known, "AgentId"), Scalar(known, "Tool"), Scalar(known, "ToolAction"), Scalar(known, "Capability")));
        Assert.Equal("Allow", Scalar(known, "InputDecision"));
        Assert.Equal("development", Scalar(known, "ClientId"));

        var unknown = Assert.Single(entries, entry => Scalar(entry, "CorrelationId") == "agent-audit-unknown");
        Assert.Equal(("Block", "UnknownAgent"), (Scalar(unknown, "Decision"), Scalar(unknown, "AgentActionReason")));
        Assert.Equal("(unknown)", Scalar(unknown, "AgentId"));
        Assert.DoesNotContain(factory.LogSink.Events, entry => entry.RenderMessage(System.Globalization.CultureInfo.InvariantCulture).Contains(marker, StringComparison.Ordinal)
            || entry.Properties.Values.Any(value => value.ToString().Contains(marker, StringComparison.Ordinal)));
    }

    [Fact]
    public async Task ActivityStoreFails_TheAuditLogStillRecordsTheDecision_AndTheCallerGetsNone()
    {
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.AddSingleton<ISecurityActivityStore, FailingStore>()));
        using var client = host.CreateClient();
        using var request = Request("""{"agentId":"research-agent","tool":"data","action":"read","capability":"data:read"}""", DevelopmentKey, "agent-store-fails");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.DoesNotContain("Allow", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
        Assert.Contains(factory.LogSink.Events, entry =>
            entry.Properties.ContainsKey("AgentActionReason") && Scalar(entry, "CorrelationId") == "agent-store-fails" && Scalar(entry, "Decision") == "Allow");
    }

    [Theory]
    [InlineData("AgentAuthorization:Agents:Bad Agent:Clients:0", "development")]
    [InlineData("AgentAuthorization:Agents:support-agent:Capabilities:9", "data:*")]
    [InlineData("AgentAuthorization:Agents:support-agent:Capabilities:9", "admin:all")]
    [InlineData("AgentAuthorization:Agents:support-agent:Capabilities:9", "shell:exec")]
    [InlineData("AgentAuthorization:Agents:support-agent:Clients:1", "test-analyzer")]
    [InlineData("AgentAuthorization:Agents:support-agent:Clients:1", "unconfigured-runtime")]
    public void InvalidAgentConfiguration_FailsAtStartup(string key, string value)
    {
        using var misconfigured = factory.WithWebHostBuilder(builder => builder.UseSetting(key, value));

        var exception = Assert.ThrowsAny<Exception>(() => misconfigured.CreateClient());

        var validation = SelfAndInner(exception).OfType<OptionsValidationException>().ToList();
        Assert.NotEmpty(validation);
        Assert.Contains(validation, candidate => candidate.Message.Contains("AgentAuthorization:Agents", StringComparison.Ordinal));
        Assert.DoesNotContain(validation, candidate => candidate.Message.Contains(value, StringComparison.Ordinal));
    }

    [Fact]
    public void AnAgentBoundToNoClient_FailsAtStartup()
    {
        using var misconfigured = factory.WithWebHostBuilder(builder => builder.UseSetting("AgentAuthorization:Agents:lonely-agent:Capabilities:0", "data:read"));

        var exception = Assert.ThrowsAny<Exception>(() => misconfigured.CreateClient());

        Assert.Contains(SelfAndInner(exception).OfType<OptionsValidationException>(), candidate => candidate.Message.Contains("lonely-agent:Clients is empty", StringComparison.Ordinal));
    }

    [Fact]
    public void AgentActionAuditEntriesHiddenByTheLogLevel_OutsideDevelopment_FailAtStartup()
    {
        // The agent sink has its own logger category: hiding only it must stop the API like hiding the firewall's events.
        using var production = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Cors:AllowedOrigins:0", "https://console.example");
            builder.UseSetting("Serilog:MinimumLevel:Override:AgentShield.Infrastructure.SecurityEvents.LoggingAgentActionEventSink", "Warning");
        });

        var exception = Assert.ThrowsAny<Exception>(() => production.CreateClient());

        Assert.NotEmpty(SelfAndInner(exception).OfType<OptionsValidationException>());
    }

    [Fact]
    public async Task Production_StartsWithoutAgents_AndBlocksEveryAgentAction()
    {
        using var production = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Cors:AllowedOrigins:0", "https://console.example");
            builder.UseSetting("Authentication:Clients:prod-runtime:KeyHashes:0", TestApiKeys.Hash("prod-runtime-key-0123456789abcdefghijklmnop"));
            builder.UseSetting("Authentication:Clients:prod-runtime:Permissions:0", "agent:authorize");
        });

        var data = await AuthorizeAsync(production, """{"agentId":"support-agent","tool":"data","action":"read","capability":"data:read"}""", "prod-runtime-key-0123456789abcdefghijklmnop");

        Assert.Equal(("Block", "UnknownAgent"), (data.GetProperty("decision").GetString(), data.GetProperty("reason").GetString()));
    }

    private static async Task<JsonElement> AuthorizeAsync(WebApplicationFactory<Program> host, string body, string apiKey, string? correlationId = null)
    {
        using var client = host.CreateClient();
        client.DefaultRequestHeaders.Remove(TestApiKeys.HeaderName);
        using var request = Request(body, apiKey, correlationId);
        using var response = await client.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, text);
        using var document = JsonDocument.Parse(text);
        return document.RootElement.GetProperty("data").Clone();
    }

    private static HttpRequestMessage Request(string body, string apiKey, string? correlationId)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, Route) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        request.Headers.Add(TestApiKeys.HeaderName, apiKey);
        if (correlationId is not null)
        {
            request.Headers.Add("X-Correlation-ID", correlationId);
        }

        return request;
    }

    private static string? Scalar(LogEvent entry, string property) =>
        entry.Properties.TryGetValue(property, out var value) && value is ScalarValue scalar ? scalar.Value?.ToString() : null;

    private static IEnumerable<Exception> SelfAndInner(Exception exception)
    {
        yield return exception;
        IEnumerable<Exception> inner = exception is AggregateException aggregate ? aggregate.InnerExceptions : exception.InnerException is { } single ? [single] : [];
        foreach (var nested in inner.SelectMany(SelfAndInner))
        {
            yield return nested;
        }
    }

    private sealed class FailingStore : ISecurityActivityStore
    {
        public ValueTask AppendAsync(SecurityActivityRecord record, CancellationToken cancellationToken) =>
            ValueTask.FromException(new InvalidOperationException("activity store down"));

        public ValueTask<SecurityActivitySlice> QueryAsync(SecurityActivityQuery query, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }
}
