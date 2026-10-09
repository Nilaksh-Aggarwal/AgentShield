using AgentShield.Api.Http;
using Microsoft.Extensions.Options;
using Serilog;
using Serilog.Events;

namespace AgentShield.Api.Logging;

internal static class LoggingSetup
{
    /// <summary>
    /// Serilog behind <c>Microsoft.Extensions.Logging</c>: application code logs through
    /// <c>ILogger&lt;T&gt;</c> with message templates; sinks and levels come from the <c>Serilog</c>
    /// configuration section.
    /// </summary>
    public static IServiceCollection AddAgentShieldLogging(this IServiceCollection services, IConfiguration configuration)
    {
        // preserveStaticLogger: the logger is owned by the host (disposed with it), so parallel test hosts
        // don't fight over Serilog's static Log.Logger.
        services.AddSerilog(
            (provider, logger) => logger
                .ReadFrom.Configuration(configuration)
                .ReadFrom.Services(provider)
                .Enrich.FromLogContext()
                .Enrich.WithProperty("Application", "AgentShield.Api")
                .Enrich.With<RequestPathRemovalEnricher>()
                .Enrich.With<SensitiveDataRedactionEnricher>(),
            preserveStaticLogger: true);

        // Security events are the audit trail (the log is its only store so far), and an Allow is logged at Information.
        // Outside Development a minimum level that hides them stops the application at startup, as disabling rate
        // limiting does; Development only warns (Program.cs). Checked with ApiOptions because it needs the built logger.
        services.AddOptions<ApiOptions>()
            .Validate<ILoggerFactory, IHostEnvironment>(
                (_, loggerFactory, environment) =>
                    environment.IsDevelopment() || AgentShield.Infrastructure.DependencyInjection.IsSecurityAuditLogEnabled(loggerFactory),
                "The Serilog minimum level hides security events, the audit trail: outside Development, AgentShield.Infrastructure.SecurityEvents must log at Information.");

        return services;
    }

    public static IApplicationBuilder UseAgentShieldRequestLogging(this WebApplication app)
    {
        return app.UseSerilogRequestLogging(options =>
        {
            // Use the host's logger (not the static Log.Logger).
            options.Logger = app.Services.GetRequiredService<Serilog.ILogger>();
            options.MessageTemplate = "HTTP {RequestMethod} {Endpoint} responded {StatusCode} in {Elapsed:0.0} ms";

            // The route template, never the raw path: the caller chooses the path, also without a key, so it could carry a
            // key, attack text or a forged log line. (The query string was never logged.)
            options.GetMessageTemplateProperties = (httpContext, _, elapsed, statusCode) =>
            [
                new LogEventProperty("RequestMethod", new ScalarValue(httpContext.Request.Method)),
                new LogEventProperty("Endpoint", new ScalarValue(EndpointNames.Describe(httpContext))),
                new LogEventProperty("StatusCode", new ScalarValue(statusCode)),
                new LogEventProperty("Elapsed", new ScalarValue(elapsed)),
            ];

            // Health probes are polled constantly; keep them out of Information-level logs.
            options.GetLevel = (httpContext, _, exception) =>
                exception is not null || httpContext.Response.StatusCode >= StatusCodes.Status500InternalServerError
                    ? LogEventLevel.Error
                    : httpContext.Request.Path.StartsWithSegments("/health", StringComparison.OrdinalIgnoreCase)
                        ? LogEventLevel.Verbose
                        : LogEventLevel.Information;
        });
    }
}
