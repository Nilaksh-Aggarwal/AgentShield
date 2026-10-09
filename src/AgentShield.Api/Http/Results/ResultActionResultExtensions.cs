using AgentShield.Application.Common.Results;
using Microsoft.AspNetCore.Mvc;

namespace AgentShield.Api.Http.Results;

/// <summary>
/// Centralised Result → HTTP mapping for controllers. Controllers choose the success status that
/// matches the operation's semantics; failures are always mapped the same way.
/// </summary>
/// <example>
/// <code>
/// var result = await _useCase.ExecuteAsync(request, cancellationToken);
/// return result.ToOkResult();
/// </code>
/// </example>
public static class ResultActionResultExtensions
{
    /// <summary>200 OK with the value in the standard envelope.</summary>
    public static IActionResult ToOkResult<T>(this Result<T> result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return result.IsSuccess
            ? new EnvelopeActionResult<T>(result.Value, StatusCodes.Status200OK)
            : new ProblemActionResult(result.Errors);
    }

    /// <summary>201 Created with a <c>Location</c> header and the created resource in the envelope.</summary>
    public static IActionResult ToCreatedResult<T>(this Result<T> result, Func<T, string> location)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(location);
        return result.IsSuccess
            ? new EnvelopeActionResult<T>(result.Value, StatusCodes.Status201Created, location(result.Value))
            : new ProblemActionResult(result.Errors);
    }

    /// <summary>202 Accepted for work that continues asynchronously; optionally points at a status resource.</summary>
    public static IActionResult ToAcceptedResult<T>(this Result<T> result, Func<T, string>? location = null)
    {
        ArgumentNullException.ThrowIfNull(result);
        return result.IsSuccess
            ? new EnvelopeActionResult<T>(result.Value, StatusCodes.Status202Accepted, location?.Invoke(result.Value))
            : new ProblemActionResult(result.Errors);
    }

    /// <summary>204 No Content (no body) on success.</summary>
    public static IActionResult ToNoContentResult(this Result result)
    {
        ArgumentNullException.ThrowIfNull(result);
        return result.IsSuccess ? new NoContentResult() : new ProblemActionResult(result.Errors);
    }

    /// <summary>Problem Details for errors produced outside a use case (e.g. the validation filter).</summary>
    public static IActionResult ToProblemResult(this IReadOnlyList<Error> errors)
    {
        ArgumentNullException.ThrowIfNull(errors);
        if (errors.Count == 0)
        {
            throw new ArgumentException("At least one error is required.", nameof(errors));
        }

        return new ProblemActionResult(errors);
    }
}
