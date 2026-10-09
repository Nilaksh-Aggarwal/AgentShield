using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Serilog;
using Serilog.Context;

namespace AgentShield.Api.Auth;

/// <summary>
/// Authentication (API key scheme) and authorization (permission policies). See
/// docs/decisions/0014-api-boundary-hardening.md.
/// </summary>
/// <remarks>
/// Secure by default: the fallback policy requires an authenticated client on every endpoint that does not declare
/// otherwise, so a new endpoint is never public by accident. Public endpoints (health probes) opt out explicitly.
/// A future identity provider (e.g. JWT bearer) is added as a second scheme that issues the same
/// <see cref="Permissions.ClaimType"/> claims; policies and endpoints stay unchanged.
/// </remarks>
internal static class AuthSetup
{
    public static IServiceCollection AddAgentShieldAuth(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<ApiAuthenticationOptions>()
            .Bind(configuration.GetSection(ApiAuthenticationOptions.SectionName))
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<ApiAuthenticationOptions>, ApiAuthenticationOptionsValidator>();
        services.AddSingleton<ApiClientRegistry>();

        services.AddAuthentication(ApiKeys.Scheme)
            .AddScheme<AuthenticationSchemeOptions, ApiKeyAuthenticationHandler>(ApiKeys.Scheme, configureOptions: null);

        var authenticatedClient = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder(ApiKeys.Scheme)
            .RequireAuthenticatedUser()
            .Build();

        services.AddAuthorizationBuilder()
            .SetDefaultPolicy(authenticatedClient)
            .SetFallbackPolicy(authenticatedClient)
            .AddPolicy(AuthorizationPolicies.FirewallAnalyze, policy => policy
                .AddAuthenticationSchemes(ApiKeys.Scheme)
                .RequireAuthenticatedUser()
                .RequireClaim(Permissions.ClaimType, Permissions.FirewallAnalyze))
            .AddPolicy(AuthorizationPolicies.ActivityRead, policy => policy
                .AddAuthenticationSchemes(ApiKeys.Scheme)
                .RequireAuthenticatedUser()
                .RequireClaim(Permissions.ClaimType, Permissions.ActivityRead))
            .AddPolicy(AuthorizationPolicies.AgentAuthorize, policy => policy
                .AddAuthenticationSchemes(ApiKeys.Scheme)
                .RequireAuthenticatedUser()
                .RequireClaim(Permissions.ClaimType, Permissions.AgentAuthorize))
            .AddPolicy(AuthorizationPolicies.ToolExecute, policy => policy
                .AddAuthenticationSchemes(ApiKeys.Scheme)
                .RequireAuthenticatedUser()
                .RequireClaim(Permissions.ClaimType, Permissions.ToolExecute))
            .AddPolicy(AuthorizationPolicies.AgentApprove, policy => policy
                .AddAuthenticationSchemes(ApiKeys.Scheme)
                .RequireAuthenticatedUser()
                .RequireClaim(Permissions.ClaimType, Permissions.AgentApprove));

        return services;
    }

    /// <summary>Authentication, the client log context, then authorization.</summary>
    public static WebApplication UseAgentShieldAuth(this WebApplication app)
    {
        app.UseAuthentication();
        app.UseMiddleware<ClientLogContextMiddleware>();
        app.UseAuthorization();
        return app;
    }
}

/// <summary>
/// Adds the authenticated client ID to every log line of the request (including security events, 403 and 429 logs)
/// and to the request completion log. Anonymous requests carry none.
/// </summary>
internal sealed class ClientLogContextMiddleware(RequestDelegate next, IDiagnosticContext diagnosticContext)
{
    public const string PropertyName = "ClientId";

    public async Task InvokeAsync(HttpContext context)
    {
        var clientId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        if (clientId is null)
        {
            await next(context);
            return;
        }

        diagnosticContext.Set(PropertyName, clientId);
        using (LogContext.PushProperty(PropertyName, clientId))
        {
            await next(context);
        }
    }
}
