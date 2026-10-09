using AgentShield.AI;
using AgentShield.Api;
using AgentShield.Api.Auth;
using AgentShield.Api.Correlation;
using AgentShield.Api.Health;
using AgentShield.Api.Http;
using AgentShield.Api.Logging;
using AgentShield.Api.OpenApi;
using AgentShield.Application;
using AgentShield.Infrastructure;
using AgentShield.Security;
using Microsoft.Extensions.Options;
using Serilog;

try
{
    var builder = WebApplication.CreateBuilder(args);

    builder.Services
        .AddApplication()
        .AddInfrastructure(builder.Configuration)
        .AddAI(builder.Configuration)
        .AddSecurity()
        .AddApiPresentation(builder.Configuration);

    var app = builder.Build();

    // Order matters: correlation first (so every log line and response carries it), then request logging,
    // then exception handling so that request logging observes the final status code. Security headers are added
    // to every response, errors included. Routing runs implicitly before all of these, so CORS, authentication,
    // authorization and rate limiting see the selected endpoint; the order below is docs/architecture/overview.md
    // "Request flow".
    app.UseMiddleware<CorrelationIdMiddleware>();
    app.UseAgentShieldRequestLogging();
    app.UseExceptionHandler();
    app.UseStatusCodePages();
    app.UseMiddleware<SecurityHeadersMiddleware>();

    if (!app.Environment.IsDevelopment())
    {
        app.UseHsts();
    }

    app.UseHttpsRedirection();

    if (app.Services.GetRequiredService<IOptions<ApiOptions>>().Value.IsSwaggerEnabled(app.Environment))
    {
        app.UseAgentShieldSwagger();
    }

    // CORS before authentication: a preflight carries no credentials and must not be challenged.
    app.UseCors();
    app.UseAgentShieldAuth();

    // After authorization: limits are per authenticated client, and a 401/403 never consumes a client's budget.
    app.UseRateLimiter();

    // Controllers get their rate-limit policy from ApiControllerBase (Standard) or their own attribute (Firewall).
    app.MapControllers();
    app.MapAgentShieldHealthChecks();

    var apiClients = app.Services.GetRequiredService<ApiClientRegistry>().ClientCount;
    if (apiClients == 0)
    {
        app.Logger.LogWarning("No API clients are configured (Authentication:Clients): every protected endpoint answers 401.");
    }
    else if (app.Logger.IsEnabled(LogLevel.Information))
    {
        app.Logger.LogInformation("{ApiClientCount} API client(s) configured.", apiClients);
    }

    if (!AgentShield.Infrastructure.DependencyInjection.IsDatabaseConfigured(app.Configuration))
    {
        app.Logger.LogWarning(
            "No connection string 'ConnectionStrings:{ConnectionStringName}' configured: persistence is disabled and /health/ready does not check PostgreSQL.",
            AgentShield.Infrastructure.Persistence.DatabaseOptions.ConnectionStringName);
    }

    // Outside Development startup validation refuses this configuration (LoggingSetup).
    if (app.Environment.IsDevelopment()
        && !AgentShield.Infrastructure.DependencyInjection.IsSecurityAuditLogEnabled(app.Services.GetRequiredService<ILoggerFactory>()))
    {
        app.Logger.LogWarning("The log level hides security events: decisions are made without an audit record (allowed in Development only).");
    }

    if (!AgentShield.AI.DependencyInjection.IsEnabled(app.Configuration))
    {
        app.Logger.LogInformation("AI-assisted analysis is disabled: decisions use the deterministic pipeline only.");
    }
    else if (app.Logger.IsEnabled(LogLevel.Information))
    {
        // Whether a key is configured, never the key itself.
        var ai = app.Services.GetRequiredService<IOptions<AiOptions>>().Value;
        app.Logger.LogInformation(
            "AI-assisted analysis is enabled: provider {AiProvider}, model {AiModel}, API key configured: {AiApiKeyConfigured}.",
            ai.Provider,
            ai.Model,
            !string.IsNullOrWhiteSpace(ai.Gemini?.ApiKey));
    }

    // Not app.RunAsync(): it disposes the host when startup fails (e.g. invalid configuration), and an in-memory test host
    // (WebApplicationFactory) may still be attaching to it, which then reports the disposal instead of the startup failure
    // (X-05). A host that never started is left to the process; a host that ran is disposed after shutdown.
    await app.StartAsync();
    try
    {
        await app.WaitForShutdownAsync();
    }
    finally
    {
        await app.DisposeAsync();
    }
}
catch (Exception exception) when (exception is not HostAbortedException)
{
    // The host's logger may not exist yet (e.g. invalid configuration); use a minimal console logger.
    using var startupLogger = new LoggerConfiguration()
        .WriteTo.Console(formatProvider: System.Globalization.CultureInfo.InvariantCulture)
        .CreateLogger();
    startupLogger.Fatal(exception, "AgentShield API terminated unexpectedly during startup or shutdown.");
    throw;
}
