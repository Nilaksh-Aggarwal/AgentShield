using AgentShield.Api.Correlation;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace AgentShield.Api.Cors;

/// <summary>Browser origins allowed to call the API cross-origin (section <c>Cors</c>).</summary>
/// <remarks>
/// Empty (the committed appsettings.json) means no cross-origin browser access: same-origin and non-browser clients are
/// unaffected. The development frontend uses the Vite proxy (same origin) and needs no entry; Development lists the Vite
/// origin only for a frontend pointed directly at the API.
/// </remarks>
public sealed class ApiCorsOptions
{
    public const string SectionName = "Cors";

    /// <summary>Exact origins (<c>scheme://host[:port]</c>, no path or trailing slash). Never <c>*</c>.</summary>
    public IList<string> AllowedOrigins { get; } = [];

    /// <summary>
    /// Whether <paramref name="origin"/> is an exact origin: absolute http(s) URI with nothing after the authority.
    /// Outside Development only https is accepted.
    /// </summary>
    internal static bool IsValidOrigin(string? origin, bool allowHttp) =>
        Uri.TryCreate(origin, UriKind.Absolute, out var uri)
        && (uri.Scheme == Uri.UriSchemeHttps || (allowHttp && uri.Scheme == Uri.UriSchemeHttp))
        && string.IsNullOrEmpty(uri.UserInfo)
        && string.Equals(uri.GetLeftPart(UriPartial.Authority), origin, StringComparison.Ordinal);
}

/// <summary>
/// CORS as an explicit allow-list: configured origins only, the methods and request headers the API uses, no
/// credentials (the API does not use cookies), and the correlation and retry headers exposed to scripts.
/// </summary>
internal static class CorsSetup
{
    /// <summary>Preflight results may be cached by the browser for this long.</summary>
    public static readonly TimeSpan PreflightMaxAge = TimeSpan.FromMinutes(10);

    private static readonly string[] AllowedMethods = [HttpMethods.Get, HttpMethods.Post];

    private static readonly string[] AllowedHeaders = [HeaderNames.Accept, HeaderNames.ContentType, CorrelationIdMiddleware.HeaderName];

    private static readonly string[] ExposedHeaders = [CorrelationIdMiddleware.HeaderName, HeaderNames.RetryAfter];

    public static IServiceCollection AddAgentShieldCors(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<ApiCorsOptions>()
            .Bind(configuration.GetSection(ApiCorsOptions.SectionName))
            .Validate<IHostEnvironment>(
                (options, environment) => options.AllowedOrigins.All(origin => ApiCorsOptions.IsValidOrigin(origin, allowHttp: environment.IsDevelopment())),
                "Cors:AllowedOrigins must contain exact origins (scheme://host[:port], no path, no trailing slash, no wildcard); outside Development only https origins.")
            .ValidateOnStart();

        services.AddCors();
        services.AddOptions<Microsoft.AspNetCore.Cors.Infrastructure.CorsOptions>()
            .Configure<IOptions<ApiCorsOptions>>((cors, settings) => cors.AddDefaultPolicy(policy => policy
                .WithOrigins([.. settings.Value.AllowedOrigins])
                .WithMethods(AllowedMethods)
                .WithHeaders(AllowedHeaders)
                .WithExposedHeaders(ExposedHeaders)
                .SetPreflightMaxAge(PreflightMaxAge)));

        return services;
    }
}
