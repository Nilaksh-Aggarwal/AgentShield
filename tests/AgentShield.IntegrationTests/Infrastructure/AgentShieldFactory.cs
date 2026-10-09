using System.Collections.Concurrent;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Serilog.Core;
using Serilog.Events;

namespace AgentShield.IntegrationTests.Infrastructure;

/// <summary>Boots the complete composition root (all layers) in memory with a log-capturing sink.</summary>
public class AgentShieldFactory : WebApplicationFactory<Program>
{
    public CollectingSink LogSink { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        // Development enables ValidateOnBuild/ValidateScopes, so a broken DI graph fails the host.
        builder.UseEnvironment("Development");
        builder.UseSetting("Serilog:MinimumLevel:Default", "Information");

        // Development loads the developer's User Secrets, which may enable AI and hold a real key. Tests never use either:
        // AI is off and the key blank unless a test enables it explicitly against a fake Gemini API.
        builder.UseSetting("Ai:Enabled", "false");
        builder.UseSetting("Ai:Gemini:ApiKey", "");

        // Clients authenticate as test-analyzer (ConfigureClient); limits stay far above what any test sends.
        TestApiKeys.Configure(builder);
        builder.UseSetting("RateLimiting:Firewall:PermitLimit", "100000");
        builder.UseSetting("RateLimiting:Standard:PermitLimit", "100000");

        // Picked up by ReadFrom.Services in the Serilog configuration.
        builder.ConfigureTestServices(services => services.AddSingleton<ILogEventSink>(LogSink));
    }

    protected override void ConfigureClient(HttpClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        base.ConfigureClient(client);
        client.DefaultRequestHeaders.Add(TestApiKeys.HeaderName, TestApiKeys.Analyzer);
    }
}

public sealed class CollectingSink : ILogEventSink
{
    private readonly ConcurrentQueue<LogEvent> _events = new();

    public IReadOnlyCollection<LogEvent> Events => _events;

    public void Emit(LogEvent logEvent) => _events.Enqueue(logEvent);
}
