using System.Net.Mime;
using AgentShield.Api.Http.Errors;
using AgentShield.Application.Common.Results;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Infrastructure;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace AgentShield.Api.Http.Results;

/// <summary>
/// Writes a failed <see cref="Result"/> as RFC 9457 Problem Details.
/// </summary>
/// <remarks>
/// <list type="bullet">
/// <item>All errors of type <see cref="ErrorType.Validation"/> → 422 <see cref="ValidationProblemDetails"/>
/// with an <c>errors</c> map keyed by camelCase property path.</item>
/// <item>Otherwise the first error decides the status (<see cref="ErrorStatusCodes"/>), its message becomes
/// <c>detail</c> and its code <c>errorCode</c>; additional errors are listed under <c>errors</c>.</item>
/// </list>
/// Error metadata is deliberately not serialised: it may carry internal context.
/// Problem Details are created through MVC's <see cref="ProblemDetailsFactory"/> so the global
/// customisation (correlationId, timestamp, errorCode) applies uniformly.
/// </remarks>
internal sealed class ProblemActionResult(IReadOnlyList<Error> errors) : IActionResult
{
    public Task ExecuteResultAsync(ActionContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        var httpContext = context.HttpContext;
        var factory = httpContext.RequestServices.GetRequiredService<ProblemDetailsFactory>();

        var problem = errors.All(error => error.Type == ErrorType.Validation)
            ? CreateValidationProblem(factory, httpContext)
            : CreateProblem(factory, httpContext);

        var result = new ObjectResult(problem) { StatusCode = problem.Status };
        result.ContentTypes.Add(MediaTypeNames.Application.ProblemJson);

        return result.ExecuteResultAsync(context);
    }

    private ValidationProblemDetails CreateValidationProblem(ProblemDetailsFactory factory, HttpContext httpContext)
    {
        var modelState = new ModelStateDictionary();
        foreach (var error in errors)
        {
            modelState.AddModelError(PropertyPath.ToCamelCase(error.PropertyName), error.Message);
        }

        var problem = factory.CreateValidationProblemDetails(
            httpContext,
            modelState,
            StatusCodes.Status422UnprocessableEntity,
            title: "One or more validation errors occurred.");

        problem.Extensions["errorCode"] = HttpErrorCodes.ValidationFailed;
        return problem;
    }

    private ProblemDetails CreateProblem(ProblemDetailsFactory factory, HttpContext httpContext)
    {
        var primary = errors[0];

        var problem = factory.CreateProblemDetails(
            httpContext,
            ErrorStatusCodes.For(primary.Type),
            detail: primary.Message);

        problem.Extensions["errorCode"] = primary.Code;
        if (errors.Count > 1)
        {
            problem.Extensions["errors"] = errors
                .Select(error => new { code = error.Code, message = error.Message })
                .ToArray();
        }

        return problem;
    }
}
