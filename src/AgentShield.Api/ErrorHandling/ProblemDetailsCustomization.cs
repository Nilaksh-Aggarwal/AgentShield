using AgentShield.Api.Correlation;
using AgentShield.Api.Http.Errors;
using Microsoft.AspNetCore.Http.Features;

namespace AgentShield.Api.ErrorHandling;

/// <summary>
/// Adds AgentShield metadata to every Problem Details response, whichever component produced it
/// (MVC, validation filter, status-code pages, exception handler).
/// </summary>
internal static class ProblemDetailsCustomization
{
    public static void Apply(ProblemDetailsContext context)
    {
        var httpContext = context.HttpContext;
        var problem = context.ProblemDetails;
        var status = problem.Status ?? httpContext.Response.StatusCode;
        var timeProvider = httpContext.RequestServices.GetRequiredService<TimeProvider>();

        problem.Instance ??= httpContext.Request.Path;
        problem.Extensions["correlationId"] = httpContext.GetCorrelationId();
        problem.Extensions["timestamp"] = timeProvider.GetUtcNow();
        problem.Extensions.TryAdd("errorCode", HttpErrorCodes.ForStatus(status));

        // Keep the W3C trace ID for distributed tracing, but never anything else from the exception.
        if (!problem.Extensions.ContainsKey("traceId"))
        {
            var traceId = httpContext.Features.Get<IHttpActivityFeature>()?.Activity.TraceId.ToString();
            if (!string.IsNullOrEmpty(traceId))
            {
                problem.Extensions["traceId"] = traceId;
            }
        }
    }
}
