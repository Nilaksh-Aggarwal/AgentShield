using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

namespace AgentShield.Api.Http;

/// <summary>
/// Security response headers for an API that returns JSON only (OWASP REST Security Cheat Sheet), set on every
/// response, including errors, just before it starts. Rationale per header: docs/api/conventions.md, "Security headers".
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item><c>X-Content-Type-Options: nosniff</c> — a browser never reinterprets a JSON body as HTML or script.</item>
/// <item><c>Content-Security-Policy: default-src 'none'; frame-ancestors 'none'</c> — if a response is ever rendered it
/// may load nothing and cannot be framed. Not a frontend CSP: the API serves no documents.</item>
/// <item><c>X-Frame-Options: DENY</c> — the same framing protection for browsers without CSP <c>frame-ancestors</c>.</item>
/// <item><c>Cache-Control: no-store</c> — analysis results and errors are never kept by browsers or shared caches
/// (unless the endpoint set its own policy).</item>
/// </list>
/// <para>The Swagger UI (Development only by default) is an HTML application: it keeps <c>nosniff</c> but not the
/// API-only CSP, framing and caching headers, which would break it. HSTS comes from <c>UseHsts</c> outside Development;
/// the <c>Server</c> header is removed in Kestrel's options.</para>
/// </remarks>
internal sealed class SecurityHeadersMiddleware(RequestDelegate next, IOptions<ApiOptions> apiOptions, IHostEnvironment environment)
{
    public const string ContentSecurityPolicy = "default-src 'none'; frame-ancestors 'none'";

    private readonly bool _swaggerEnabled = apiOptions.Value.IsSwaggerEnabled(environment);

    public Task InvokeAsync(HttpContext context)
    {
        context.Response.OnStarting(() =>
        {
            Apply(context);
            return Task.CompletedTask;
        });

        return next(context);
    }

    private void Apply(HttpContext context)
    {
        var headers = context.Response.Headers;
        headers.XContentTypeOptions = "nosniff";

        if (_swaggerEnabled && context.Request.Path.StartsWithSegments("/swagger", StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        headers.ContentSecurityPolicy = ContentSecurityPolicy;
        headers.XFrameOptions = "DENY";
        if (!headers.ContainsKey(HeaderNames.CacheControl))
        {
            headers.CacheControl = "no-store";
        }
    }
}
