using System.Net.Mime;
using System.Text.Json;
using AgentShield.Api.RateLimiting;
using AgentShield.Application.Common.Health;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace AgentShield.Api.Health;

/// <summary>
/// <list type="bullet">
/// <item><c>/health/live</c> — the process is up. Only <see cref="HealthCheckTags.Live"/> checks; never dependencies.</item>
/// <item><c>/health/ready</c> — dependencies required to serve traffic (<see cref="HealthCheckTags.Ready"/>).</item>
/// <item><c>/health</c> — every registered check.</item>
/// </list>
/// Healthy/Degraded → 200, Unhealthy → 503. Responses never include exception details.
/// </summary>
internal static class HealthEndpoints
{
    public static IServiceCollection AddAgentShieldHealthChecks(this IServiceCollection services)
    {
        services.AddHealthChecks()
            .AddCheck("self", () => HealthCheckResult.Healthy(), tags: [HealthCheckTags.Live]);

        return services;
    }

    /// <remarks>
    /// Probes are anonymous (orchestrators do not hold API keys) and expose no details. Liveness is never rate limited,
    /// so a flood cannot make a healthy process look dead; readiness and the full report, which may query dependencies,
    /// share the generous <see cref="RateLimitPolicies.Standard"/> limit.
    /// </remarks>
    public static WebApplication MapAgentShieldHealthChecks(this WebApplication app)
    {
        app.MapHealthChecks("/health/live", CreateOptions(registration => registration.Tags.Contains(HealthCheckTags.Live)))
            .AllowAnonymous()
            .DisableRateLimiting();
        app.MapHealthChecks("/health/ready", CreateOptions(registration => registration.Tags.Contains(HealthCheckTags.Ready)))
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitPolicies.Standard);
        app.MapHealthChecks("/health", CreateOptions(_ => true))
            .AllowAnonymous()
            .RequireRateLimiting(RateLimitPolicies.Standard);

        return app;
    }

    private static HealthCheckOptions CreateOptions(Func<HealthCheckRegistration, bool> predicate) => new()
    {
        Predicate = predicate,
        ResponseWriter = WriteResponseAsync,
    };

    private static Task WriteResponseAsync(HttpContext context, HealthReport report)
    {
        var jsonOptions = context.RequestServices.GetRequiredService<IOptions<Microsoft.AspNetCore.Http.Json.JsonOptions>>().Value.SerializerOptions;

        var body = new
        {
            status = report.Status.ToString(),
            totalDurationMs = Math.Round(report.TotalDuration.TotalMilliseconds, 1),
            checks = report.Entries.Select(entry => new
            {
                name = entry.Key,
                status = entry.Value.Status.ToString(),
                durationMs = Math.Round(entry.Value.Duration.TotalMilliseconds, 1),
                description = entry.Value.Description,
            }),
        };

        context.Response.ContentType = MediaTypeNames.Application.Json;
        return JsonSerializer.SerializeAsync(context.Response.Body, body, jsonOptions, context.RequestAborted);
    }
}
