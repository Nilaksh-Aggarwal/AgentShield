using System.Net;
using System.Reflection;
using System.Text;
using System.Text.Json;
using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Activity;
using AgentShield.Application.Agents.ExecuteTool;
using AgentShield.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Serilog.Events;

namespace AgentShield.IntegrationTests.Agents;

/// <summary>
/// The tool gateway as the real composition root wires it: one execution authority that alone holds the tools (complete
/// mediation, checked over every type in every AgentShield assembly), the committed Development identity, an audit entry per
/// stage, fail-closed recording and startup validation of the gateway identities.
/// </summary>
public sealed class ToolGatewayPipelineTests(AgentShieldFactory factory) : IClassFixture<AgentShieldFactory>
{
    private const string Route = "/api/v1/agent/tools/execute";

    /// <summary>The public Development key: its client is research-agent's gateway identity (appsettings.Development.json).</summary>
    private const string DevelopmentKey = "agentshield-development-only-key-not-a-secret";

    private static readonly Assembly[] AgentShieldAssemblies =
    [
        typeof(Program).Assembly,
        typeof(IToolGateway).Assembly,
        Type.GetType("AgentShield.Domain.Agents.AgentId, AgentShield.Domain", throwOnError: true)!.Assembly,
        Type.GetType("AgentShield.Security.DependencyInjection, AgentShield.Security", throwOnError: true)!.Assembly,
        Type.GetType("AgentShield.Infrastructure.DependencyInjection, AgentShield.Infrastructure", throwOnError: true)!.Assembly,
        Type.GetType("AgentShield.AI.DependencyInjection, AgentShield.AI", throwOnError: true)!.Assembly,
    ];

    // ── Composition and complete mediation ──────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Composition_OneGatewayOneAuthority_OneTool_ItsPolicy_AndBothSinks()
    {
        using var client = factory.CreateClient();
        using var scope = factory.Services.CreateScope();
        var services = scope.ServiceProvider;

        Assert.Equal("ToolGateway", services.GetRequiredService<IToolGateway>().GetType().Name);
        Assert.Equal("ExecutionGrantAuthority", Assert.Single(services.GetServices<IToolExecutionAuthority>()).GetType().Name);
        Assert.Same(factory.Services.GetRequiredService<IToolExecutionAuthority>(), services.GetRequiredService<IToolExecutionAuthority>());
        Assert.Equal(["KnowledgeLookupTool"], services.GetServices<IToolExecutor>().Select(executor => executor.GetType().Name));
        Assert.Equal(["KnowledgeLookupArgumentPolicy"], services.GetServices<IToolArgumentPolicy>().Select(policy => policy.GetType().Name));
        Assert.Equal(
            ["LoggingToolGatewayEventSink", "ToolGatewayActivityRecorder"],
            services.GetServices<IToolGatewayEventSink>().Select(sink => sink.GetType().Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Composition_EveryExecutableAction_HasExactlyOnePolicyOneExecutorAndACatalogueEntry()
    {
        using var scope = factory.Services.CreateScope();
        var services = scope.ServiceProvider;
        var catalogue = services.GetRequiredService<IToolCatalog>();
        var executors = services.GetServices<IToolExecutor>().Select(executor => (executor.Tool, executor.Action)).ToArray();
        var policies = services.GetServices<IToolArgumentPolicy>().Select(policy => (policy.Tool, policy.Action)).ToArray();

        Assert.Equal(executors.Order(), policies.Order());
        Assert.Equal(executors.Length, executors.Distinct().Count());
        Assert.All(executors, action => Assert.NotNull(catalogue.Find(action.Tool, action.Action)));
    }

    [Fact]
    public void CompleteMediation_OnlyTheExecutionAuthorityHoldsATool_AndOnlyTheGatewayHoldsTheAuthority()
    {
        // Over every type in every AgentShield assembly: who could reach a tool executor, the authority or the gateway.
        Assert.Equal(["ExecutionGrantAuthority"], DependentsOf(typeof(IToolExecutor)));
        Assert.Equal(["ToolGateway"], DependentsOf(typeof(IToolExecutionAuthority)));
        Assert.Equal(["AgentToolsController"], DependentsOf(typeof(IToolGateway)));
    }

    [Fact]
    public void CompleteMediation_TheOneToolIsInternal_AndCannotBeResolvedAroundTheAuthority()
    {
        var implementations = AgentShieldAssemblies
            .SelectMany(assembly => assembly.GetTypes())
            .Where(type => type is { IsClass: true, IsAbstract: false } && typeof(IToolExecutor).IsAssignableFrom(type))
            .ToArray();

        var tool = Assert.Single(implementations);
        Assert.Equal("KnowledgeLookupTool", tool.Name);
        Assert.False(tool.IsPublic);
        Assert.True(tool.IsSealed);
        Assert.Null(factory.Services.GetService(tool));
    }

    // ── The committed Development identity ──────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("knowledge", "lookup", "knowledge:read", """{"query":"dependency injection"}""", "Allow", "Executed", "Permitted")]
    [InlineData("knowledge", "lookup", "knowledge:read", """{"query":"dependency injection","path":"/etc/passwd"}""", "Block", "ArgumentsRejected", "Permitted")]
    [InlineData("browser", "navigate", "browser:navigate", "{}", "Review", "HeldForReview", "HumanApprovalRequired")]
    [InlineData("email", "send", "email:send", "{}", "Block", "Denied", "CapabilityNotGranted")]
    [InlineData("data", "read", "data:read", "{}", "Block", "ToolUnavailable", "Permitted")]
    [InlineData("shell", "exec", "shell:exec", "{}", "Block", "Denied", "UnknownTool")]
    public async Task CommittedDevelopmentIdentity_IsResearchAgent_AndDecidesAsTheConsoleExpects(
        string tool, string action, string capability, string arguments, string decision, string outcome, string reason)
    {
        // The console's tool gateway preview sends these requests with the Development key.
        var data = await ExecuteAsync(factory, Body(tool, action, capability, arguments), DevelopmentKey);

        Assert.Equal((decision, outcome, reason), (data.GetProperty("decision").GetString(), data.GetProperty("outcome").GetString(), data.GetProperty("authorizationReason").GetString()));
        Assert.Equal(decision == "Allow", data.GetProperty("executed").GetBoolean());
    }

    // ── Audit log ───────────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public async Task AuditLog_AnExecution_IsRecordedStageByStage_InOrder_UnderOneSecurityEvent()
    {
        var correlationId = "gw-audit-run-" + Guid.NewGuid().ToString("N")[..8];

        var data = await ExecuteAsync(factory, Body("knowledge", "lookup", "knowledge:read", """{"query":"least privilege"}"""), DevelopmentKey, correlationId);

        var entries = GatewayEntries(correlationId);
        Assert.Equal(["ToolAuthorizationRequested", "ToolAuthorizationAllowed", "ToolExecutionStarted", "ToolExecutionCompleted"], entries.Select(entry => Scalar(entry, "ToolGatewayStage")));
        Assert.All(entries, entry => Assert.Equal(data.GetProperty("securityEventId").GetGuid().ToString(), Scalar(entry, "SecurityEventId")));
        Assert.All(entries, entry => Assert.Equal(("research-agent", "development"), (Scalar(entry, "AgentId"), Scalar(entry, "ClientId"))));
        Assert.All(entries.Skip(1), entry => Assert.Equal(data.GetProperty("executionId").GetGuid().ToString(), Scalar(entry, "ExecutionId")));
        Assert.Equal("(none)", Scalar(entries[0], "ExecutionId"));
        Assert.Equal(("knowledge", "lookup", "knowledge:read", "Executed"), (Scalar(entries[^1], "Tool"), Scalar(entries[^1], "ToolAction"), Scalar(entries[^1], "Capability"), Scalar(entries[^1], "ToolExecutionOutcome")));
        Assert.All(entries, entry => Assert.Equal(1002, ((ScalarValue)((StructureValue)entry.Properties["EventId"]).Properties.Single(property => property.Name == "Id").Value).Value));
    }

    [Fact]
    public async Task AuditLog_ARefusal_IsRequestedDecidedRejected_AtWarning()
    {
        var correlationId = "gw-audit-refuse-" + Guid.NewGuid().ToString("N")[..8];

        await ExecuteAsync(factory, Body("email", "send", "email:send", "{}"), DevelopmentKey, correlationId);

        var entries = GatewayEntries(correlationId);
        Assert.Equal(["ToolAuthorizationRequested", "ToolAuthorizationBlocked", "ToolExecutionRejected"], entries.Select(entry => Scalar(entry, "ToolGatewayStage")));
        Assert.Equal([LogEventLevel.Information, LogEventLevel.Warning, LogEventLevel.Warning], entries.Select(entry => entry.Level));
        Assert.Equal(("Block", "CapabilityNotGranted", "Denied"), (Scalar(entries[^1], "Decision"), Scalar(entries[^1], "AgentActionReason"), Scalar(entries[^1], "ToolExecutionOutcome")));
    }

    [Fact]
    public async Task AuditLog_RecordsTheArgumentRuleThatWasBroken_ButNeverTheArgumentsOrTheResult()
    {
        var marker = "zq7gwaudit" + Guid.NewGuid().ToString("N")[..8];
        var correlationId = "gw-audit-args-" + Guid.NewGuid().ToString("N")[..8];

        await ExecuteAsync(factory, Body("knowledge", "lookup", "knowledge:read", $$"""{"query":"{{marker}}","{{marker}}":"{{marker}}"}"""), DevelopmentKey, correlationId);
        await ExecuteAsync(factory, Body("knowledge", "lookup", "knowledge:read", $$"""{"query":"idempotency {{marker}}"}"""), DevelopmentKey, correlationId + "-b");
        await ExecuteAsync(factory, Body("knowledge", "lookup", "knowledge:read", """{"query":"idempotency"}"""), DevelopmentKey, correlationId + "-c");

        Assert.Equal("UnexpectedArgument", Scalar(GatewayEntries(correlationId)[^1], "ArgumentViolation"));
        Assert.DoesNotContain(factory.LogSink.Events, entry => Text(entry).Contains(marker, StringComparison.Ordinal));
        Assert.DoesNotContain(factory.LogSink.Events, entry => Text(entry).Contains("Idempotency: an operation", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ActivityStoreFails_AfterTheToolRan_TheAuditLogHasTheCompletion_AndTheCallerGetsNoResult()
    {
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.AddSingleton<ISecurityActivityStore, FailingStore>()));
        var correlationId = "gw-store-fails-" + Guid.NewGuid().ToString("N")[..8];
        using var client = host.CreateClient();
        using var request = Request(Body("knowledge", "lookup", "knowledge:read", """{"query":"fail closed"}"""), DevelopmentKey, correlationId);

        var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.DoesNotContain("Fail closed:", body, StringComparison.Ordinal);
        Assert.DoesNotContain("executed", body, StringComparison.Ordinal);
        Assert.Equal("ToolExecutionCompleted", Scalar(GatewayEntries(correlationId)[^1], "ToolGatewayStage"));
    }

    // ── Startup validation ──────────────────────────────────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("tool-only-client", null, "Authentication:Clients:tool-only-client holds tool:execute but is no agent's")]
    [InlineData(null, "test-analyzer", "support-agent:GatewayClient names a client that is not configured with the tool:execute permission.")]
    [InlineData(null, "development", "Authentication:Clients:development is the GatewayClient of 2 agents")]
    public void InvalidGatewayIdentities_FailAtStartup(string? toolOnlyClient, string? supportGatewayClient, string expected)
    {
        using var misconfigured = factory.WithWebHostBuilder(builder =>
        {
            if (toolOnlyClient is not null)
            {
                builder.UseSetting($"Authentication:Clients:{toolOnlyClient}:KeyHashes:0", TestApiKeys.Hash("tool-only-client-key-0123456789abcdefghij"));
                builder.UseSetting($"Authentication:Clients:{toolOnlyClient}:Permissions:0", "tool:execute");
            }

            if (supportGatewayClient is not null)
            {
                builder.UseSetting("AgentAuthorization:Agents:support-agent:GatewayClient", supportGatewayClient);
            }
        });

        var exception = Assert.ThrowsAny<Exception>(() => misconfigured.CreateClient());

        Assert.Contains(SelfAndInner(exception).OfType<OptionsValidationException>(), candidate => candidate.Message.Contains(expected, StringComparison.Ordinal));
    }

    [Fact]
    public void AGatewayClientNotAmongTheAgentsClients_FailsAtStartup()
    {
        using var misconfigured = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Authentication:Clients:support-gateway:KeyHashes:0", TestApiKeys.Hash("support-gateway-key-0123456789abcdefghijk"));
            builder.UseSetting("Authentication:Clients:support-gateway:Permissions:0", "tool:execute");
            builder.UseSetting("AgentAuthorization:Agents:support-agent:GatewayClient", "support-gateway");
        });

        var exception = Assert.ThrowsAny<Exception>(() => misconfigured.CreateClient());

        Assert.Contains(SelfAndInner(exception).OfType<OptionsValidationException>(), candidate =>
            candidate.Message.Contains("support-agent:GatewayClient must also be listed in AgentAuthorization:Agents:support-agent:Clients.", StringComparison.Ordinal));
    }

    [Fact]
    public async Task ADedicatedGatewayCredential_ActsAsItsAgentOnly()
    {
        // A gateway-only credential (tool:execute, nothing else) bound to support-agent: knowledge:read is research-agent's,
        // so the same lookup that research-agent may run is blocked for it.
        using var host = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Authentication:Clients:support-gateway:KeyHashes:0", TestApiKeys.Hash("support-gateway-key-0123456789abcdefghijk"));
            builder.UseSetting("Authentication:Clients:support-gateway:Permissions:0", "tool:execute");
            builder.UseSetting("AgentAuthorization:Agents:support-agent:Clients:1", "support-gateway");
            builder.UseSetting("AgentAuthorization:Agents:support-agent:GatewayClient", "support-gateway");
        });

        var data = await ExecuteAsync(host, Body("knowledge", "lookup", "knowledge:read", """{"query":"di"}"""), "support-gateway-key-0123456789abcdefghijk");

        Assert.Equal(("Block", "CapabilityNotGranted", false), (data.GetProperty("decision").GetString(), data.GetProperty("authorizationReason").GetString(), data.GetProperty("executed").GetBoolean()));
    }

    [Fact]
    public void GatewayAuditEntriesHiddenByTheLogLevel_OutsideDevelopment_FailAtStartup()
    {
        using var production = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Cors:AllowedOrigins:0", "https://console.example");
            builder.UseSetting("Serilog:MinimumLevel:Override:AgentShield.Infrastructure.SecurityEvents.LoggingToolGatewayEventSink", "Warning");
        });

        var exception = Assert.ThrowsAny<Exception>(() => production.CreateClient());

        Assert.NotEmpty(SelfAndInner(exception).OfType<OptionsValidationException>());
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────────────────────────────────────────

    /// <summary>Names of the AgentShield types that take <paramref name="dependency"/> (or a sequence, lazy or factory of it).</summary>
    private static string[] DependentsOf(Type dependency) =>
    [
        .. AgentShieldAssemblies
            .SelectMany(assembly => assembly.GetTypes())
            .Where(type => type.IsClass && !IsCompilerGenerated(type))
            .Where(type => type.GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance).SelectMany(constructor => constructor.GetParameters()).Any(parameter => Mentions(parameter.ParameterType, dependency))
                || type.GetFields(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static).Any(field => Mentions(field.FieldType, dependency)))
            .Select(type => type.Name)
            .Distinct()
            .Order(StringComparer.Ordinal),
    ];

    private static bool Mentions(Type candidate, Type dependency) =>
        candidate == dependency
        || (candidate.IsArray && Mentions(candidate.GetElementType()!, dependency))
        || (candidate.IsGenericType && candidate.GetGenericArguments().Any(argument => Mentions(argument, dependency)));

    private static bool IsCompilerGenerated(Type type) =>
        type.IsDefined(typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute), inherit: false) && type.Name.Contains('<', StringComparison.Ordinal);

    private LogEvent[] GatewayEntries(string correlationId) =>
        [.. factory.LogSink.Events.Where(entry => entry.Properties.ContainsKey("ToolGatewayStage") && Scalar(entry, "CorrelationId") == correlationId)];

    private static string Body(string tool, string action, string capability, string arguments) =>
        $$"""{"tool":"{{tool}}","action":"{{action}}","capability":"{{capability}}","arguments":{{arguments}}}""";

    private static async Task<JsonElement> ExecuteAsync(WebApplicationFactory<Program> host, string body, string apiKey, string? correlationId = null)
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

    private static string Text(LogEvent entry) =>
        entry.RenderMessage(System.Globalization.CultureInfo.InvariantCulture) + string.Concat(entry.Properties.Values.Select(value => value.ToString()));

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
