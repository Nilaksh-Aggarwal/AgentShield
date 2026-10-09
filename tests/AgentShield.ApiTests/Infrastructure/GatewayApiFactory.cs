using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace AgentShield.ApiTests.Infrastructure;

/// <summary>
/// <see cref="ApiFactory"/> plus two gateway agents, each with its own credential (its gateway identity), and a probe around
/// every registered tool executor, the real <c>knowledge.lookup</c> included, so a test can prove whether a tool ran.
/// </summary>
/// <remarks>
/// The probe wraps the executors the application registered; it does not replace them. Pass <c>withTestTools</c> to add
/// harmless test executors (and argument policies) for catalogued actions of every risk level, which production does not
/// have: the gateway architecture with more tools (Milestone 11, high-impact action model).
/// </remarks>
public class GatewayApiFactory : ApiFactory
{
    /// <summary>Holds knowledge:read, data:read, data:write, email:send, browser:navigate and payment:execute.</summary>
    public const string GatewayAgent = "test-gateway-agent";

    public const string GatewayClientId = "test-gateway-runtime";

    public const string GatewayKey = "test-gateway-runtime-key-0123456789abcdefgh";

    /// <summary>Holds data:read only: no capability for the knowledge tool.</summary>
    public const string ReaderAgent = "test-gateway-reader";

    public const string ReaderClientId = "test-gateway-reader-runtime";

    public const string ReaderKey = "test-gateway-reader-key-0123456789abcdefghij";

    private readonly bool _withTestTools;

    public GatewayApiFactory()
        : this(withTestTools: false)
    {
    }

    protected GatewayApiFactory(bool withTestTools) => _withTestTools = withTestTools;

    /// <summary>Every tool invocation that reached an executor, whatever endpoint or component caused it.</summary>
    public ToolProbe Probe => Services.GetRequiredService<ToolProbe>();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        Configure(builder);
        builder.ConfigureTestServices(services =>
        {
            if (_withTestTools)
            {
                TestTools.Register(services);
            }

            ProbeEveryTool(services);
        });
    }

    /// <summary>Registers the gateway clients and agents on a host.</summary>
    public static void Configure(IWebHostBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        Client(builder, GatewayClientId, GatewayKey);
        Client(builder, ReaderClientId, ReaderKey);
        Agent(builder, GatewayAgent, GatewayClientId, "knowledge:read", "data:read", "data:write", "email:send", "browser:navigate", "payment:execute");
        Agent(builder, ReaderAgent, ReaderClientId, "data:read");
    }

    /// <summary>Wraps every registered tool executor in a probe that records each invocation, then runs the real executor.</summary>
    public static void ProbeEveryTool(IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddSingleton<ToolProbe>();
        foreach (var descriptor in services.Where(descriptor => descriptor.ServiceType == typeof(IToolExecutor)).ToArray())
        {
            services.Remove(descriptor);
            services.AddSingleton<IToolExecutor>(provider => new ProbedToolExecutor(Create(provider, descriptor), provider.GetRequiredService<ToolProbe>()));
        }
    }

    private static IToolExecutor Create(IServiceProvider provider, ServiceDescriptor descriptor) => (IToolExecutor)(
        descriptor.ImplementationInstance
        ?? descriptor.ImplementationFactory?.Invoke(provider)
        ?? ActivatorUtilities.CreateInstance(provider, descriptor.ImplementationType!));

    private static void Client(IWebHostBuilder builder, string clientId, string key)
    {
        builder.UseSetting($"Authentication:Clients:{clientId}:KeyHashes:0", TestApiKeys.Hash(key));
        builder.UseSetting($"Authentication:Clients:{clientId}:Permissions:0", "tool:execute");
    }

    private static void Agent(IWebHostBuilder builder, string id, string client, params string[] capabilities)
    {
        for (var index = 0; index < capabilities.Length; index++)
        {
            builder.UseSetting($"AgentAuthorization:Agents:{id}:Capabilities:{index}", capabilities[index]);
        }

        builder.UseSetting($"AgentAuthorization:Agents:{id}:Clients:0", client);
        builder.UseSetting($"AgentAuthorization:Agents:{id}:GatewayClient", client);
    }
}

/// <summary>Every tool invocation an executor received: which tool, and the validated arguments it was handed.</summary>
public sealed class ToolProbe
{
    private readonly ConcurrentQueue<(string Tool, string Action, ToolArguments Arguments)> _invocations = new();

    public int Count => _invocations.Count;

    public IReadOnlyList<(string Tool, string Action, ToolArguments Arguments)> Invocations => [.. _invocations];

    internal void Record(ToolId tool, ActionName action, ToolArguments arguments) => _invocations.Enqueue((tool.Value, action.Value, arguments));
}

internal sealed class ProbedToolExecutor(IToolExecutor inner, ToolProbe probe) : IToolExecutor
{
    public ToolId Tool => inner.Tool;

    public ActionName Action => inner.Action;

    public ValueTask<ToolOutput> ExecuteAsync(ToolArguments arguments, CancellationToken cancellationToken)
    {
        probe.Record(inner.Tool, inner.Action, arguments);
        return inner.ExecuteAsync(arguments, cancellationToken);
    }
}

/// <summary>
/// Harmless test tools for catalogued actions of every risk level (data.write Medium, email.send High, payment.execute
/// Critical): an argument policy that accepts any object and an executor that only says it ran. Test-only: production
/// executes <c>knowledge.lookup</c> alone.
/// </summary>
internal static class TestTools
{
    public static readonly (string Tool, string Action)[] Actions = [("data", "write"), ("email", "send"), ("payment", "execute"), ("browser", "navigate")];

    public static void Register(IServiceCollection services)
    {
        foreach (var (tool, action) in Actions)
        {
            services.AddSingleton<IToolArgumentPolicy>(new AnyObjectPolicy(tool, action));
            services.AddSingleton<IToolExecutor>(new SaysItRanExecutor(tool, action));
        }
    }

    private sealed record TestArguments : ToolArguments;

    private sealed class AnyObjectPolicy(string tool, string action) : IToolArgumentPolicy
    {
        public ToolId Tool { get; } = new(tool);

        public ActionName Action { get; } = new(action);

        public ToolArgumentCheck Check(JsonElement arguments) =>
            arguments.ValueKind == JsonValueKind.Object ? ToolArgumentCheck.Accept(new TestArguments()) : ToolArgumentCheck.Reject(ToolArgumentViolation.NotAnObject);
    }

    private sealed class SaysItRanExecutor(string tool, string action) : IToolExecutor
    {
        public ToolId Tool { get; } = new(tool);

        public ActionName Action { get; } = new(action);

        public ValueTask<ToolOutput> ExecuteAsync(ToolArguments arguments, CancellationToken cancellationToken) =>
            ValueTask.FromResult(new ToolOutput(found: true, $"test tool {Tool}.{Action} ran"));
    }
}

/// <summary>Requests to the tool gateway with explicit control over credentials.</summary>
internal static class GatewayRequests
{
    public const string Route = "/api/v1/agent/tools/execute";

    public static string Body(string tool, string action, string capability, string arguments = """{"query":"dependency injection"}""", string? inputDecision = null) =>
        inputDecision is null
            ? $$"""{"tool":"{{tool}}","action":"{{action}}","capability":"{{capability}}","arguments":{{arguments}}}"""
            : $$"""{"tool":"{{tool}}","action":"{{action}}","capability":"{{capability}}","arguments":{{arguments}},"inputDecision":"{{inputDecision}}"}""";

    public static string Lookup(string query) =>
        Body("knowledge", "lookup", "knowledge:read", JsonSerializer.Serialize(new Dictionary<string, string> { ["query"] = query }));

    public static async Task<HttpResponseMessage> SendAsync(WebApplicationFactory<Program> host, string body, string? apiKey = GatewayApiFactory.GatewayKey, string? correlationId = null)
    {
        using var client = AnalyzeRequests.CreateAnonymousClient(host);
        using var request = new HttpRequestMessage(HttpMethod.Post, Route) { Content = new StringContent(body, Encoding.UTF8, "application/json") };
        if (apiKey is not null)
        {
            request.Headers.Add(TestApiKeys.HeaderName, apiKey);
        }

        if (correlationId is not null)
        {
            request.Headers.Add("X-Correlation-ID", correlationId);
        }

        return await client.SendAsync(request);
    }
}
