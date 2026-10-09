using System.Globalization;
using System.Security.Claims;
using System.Threading.RateLimiting;
using AgentShield.Api.Http;
using AgentShield.Api.Http.Errors;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Extensions.Options;

namespace AgentShield.Api.RateLimiting;

/// <summary>
/// ASP.NET Core rate limiting with in-process fixed windows, partitioned per authenticated client (per remote address
/// for anonymous endpoints). See docs/decisions/0014-api-boundary-hardening.md.
/// </summary>
/// <remarks>
/// <para>The limiter runs after authorization, so it partitions by the authenticated client ID, and requests that fail
/// authentication (401) are rejected before they consume a client's budget.</para>
/// <para>Replacing the in-memory limiter with a distributed one (several instances) means changing only
/// <see cref="CreatePartition"/>: endpoints reference policy names, and the firewall use case knows nothing about rate
/// limiting.</para>
/// </remarks>
internal static partial class RateLimitingSetup
{
    public static IServiceCollection AddAgentShieldRateLimiting(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<RateLimitingOptions>()
            .Bind(configuration.GetSection(RateLimitingOptions.SectionName))
            .Validate(options => options.Firewall.IsValid(),
                $"RateLimiting:Firewall needs PermitLimit 1-{RateLimitingOptions.MaxPermitLimit}, WindowSeconds 1-{RateLimitingOptions.MaxWindowSeconds} and QueueLimit 0-{RateLimitingOptions.MaxQueueLimit}.")
            .Validate(options => options.Standard.IsValid(),
                $"RateLimiting:Standard needs PermitLimit 1-{RateLimitingOptions.MaxPermitLimit}, WindowSeconds 1-{RateLimitingOptions.MaxWindowSeconds} and QueueLimit 0-{RateLimitingOptions.MaxQueueLimit}.")
            .Validate<IHostEnvironment>((options, environment) => options.Enabled || environment.IsDevelopment(),
                "RateLimiting:Enabled may be false only in the Development environment.")
            .ValidateOnStart();

        services.AddRateLimiter(options =>
        {
            options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
            options.OnRejected = OnRejectedAsync;
        });

        services.AddOptions<RateLimiterOptions>()
            .Configure<IOptions<RateLimitingOptions>>((limiter, settings) =>
            {
                var value = settings.Value;
                limiter.AddPolicy(RateLimitPolicies.Firewall, context => CreatePartition(context, value.Enabled, value.Firewall));
                limiter.AddPolicy(RateLimitPolicies.Standard, context => CreatePartition(context, value.Enabled, value.Standard));
            });

        return services;
    }

    /// <summary>
    /// The limiter for one request: a fixed window per partition key. The key is the authenticated client ID, or the
    /// remote address for anonymous requests (behind a reverse proxy that is the proxy's address unless forwarded
    /// headers are configured for known proxies; see docs/api/conventions.md).
    /// </summary>
    internal static RateLimitPartition<string> CreatePartition(HttpContext context, bool enabled, RateLimitPolicyOptions policy)
    {
        if (!enabled)
        {
            return RateLimitPartition.GetNoLimiter(string.Empty);
        }

        var clientId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
        var key = clientId is not null
            ? "client:" + clientId
            : "address:" + (context.Connection.RemoteIpAddress?.ToString() ?? "unknown");

        return RateLimitPartition.GetFixedWindowLimiter(key, _ => new FixedWindowRateLimiterOptions
        {
            PermitLimit = policy.PermitLimit,
            Window = TimeSpan.FromSeconds(policy.WindowSeconds),
            QueueLimit = policy.QueueLimit,
            QueueProcessingOrder = QueueProcessingOrder.OldestFirst,
            AutoReplenishment = true,
        });
    }

    /// <summary>429 as Problem Details with <c>Retry-After</c>; logs the policy, endpoint and client, never limiter internals.</summary>
    private static async ValueTask OnRejectedAsync(OnRejectedContext context, CancellationToken cancellationToken)
    {
        var httpContext = context.HttpContext;

        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            var seconds = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));
            httpContext.Response.Headers.RetryAfter = seconds.ToString(CultureInfo.InvariantCulture);
        }

        var logger = httpContext.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger(typeof(RateLimitingSetup).FullName!);
        LogRejected(
            logger,
            httpContext.GetEndpoint()?.Metadata.GetMetadata<EnableRateLimitingAttribute>()?.PolicyName ?? "(none)",
            httpContext.Request.Method,
            EndpointNames.Describe(httpContext),
            httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "(anonymous)");

        var problemDetails = httpContext.RequestServices.GetRequiredService<IProblemDetailsService>();
        await problemDetails.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails = new ProblemDetails
            {
                // The framework has no default type for 429 (it does for 400-415, 422, 500); RFC 6585 defines it.
                Type = "https://tools.ietf.org/html/rfc6585#section-4",
                Status = StatusCodes.Status429TooManyRequests,
                Title = "Too many requests.",
                Detail = "The request rate limit was exceeded. Retry after the number of seconds in the Retry-After header.",
                Extensions = { ["errorCode"] = HttpErrorCodes.ForStatus(StatusCodes.Status429TooManyRequests) },
            },
        });
    }

    [LoggerMessage(EventId = 2100, Level = LogLevel.Warning, Message = "Rate limit {RateLimitPolicy} exceeded for {RequestMethod} {Endpoint} by client {ClientId}")]
    private static partial void LogRejected(ILogger logger, string rateLimitPolicy, string requestMethod, string endpoint, string clientId);
}
