using AgentShield.Api.Correlation;
using AgentShield.Api.Http.Responses;
using Microsoft.AspNetCore.Mvc;

namespace AgentShield.Api.Http.Results;

/// <summary>
/// Writes a successful value as <see cref="ApiResponse{T}"/> with the given status code.
/// The envelope metadata is resolved at execution time from the current request.
/// </summary>
internal sealed class EnvelopeActionResult<T>(T data, int statusCode, string? location = null) : IActionResult
{
    public Task ExecuteResultAsync(ActionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var httpContext = context.HttpContext;
        var timeProvider = httpContext.RequestServices.GetRequiredService<TimeProvider>();
        var meta = new ApiResponseMeta(httpContext.GetCorrelationId(), timeProvider.GetUtcNow());

        if (location is not null)
        {
            httpContext.Response.Headers.Location = location;
        }

        return new ObjectResult(new ApiResponse<T>(data, meta)) { StatusCode = statusCode }
            .ExecuteResultAsync(context);
    }
}
