using AgentShield.Api.Http;
using AgentShield.Api.Http.Errors;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace AgentShield.Api.ErrorHandling;

/// <summary>
/// Last line of defence for exceptions that escape controllers and use cases. Logs once, then writes
/// Problem Details that never contain exception messages, stack traces or infrastructure details —
/// in any environment. Expected failures must be returned as <c>Result</c>, not thrown.
/// </summary>
internal sealed partial class GlobalExceptionHandler(
    IProblemDetailsService problemDetailsService,
    ILogger<GlobalExceptionHandler> logger) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        if (exception is OperationCanceledException && httpContext.RequestAborted.IsCancellationRequested)
        {
            // The client went away; there is nobody to respond to.
            logger.LogInformation("Request was cancelled by the client.");
            return true;
        }

        int statusCode;
        string title;
        if (exception is BadHttpRequestException badRequest)
        {
            // Raised by the server for malformed or oversized requests (e.g. 400, 413). The status is safe to surface.
            statusCode = badRequest.StatusCode;
            title = statusCode == StatusCodes.Status413PayloadTooLarge
                ? "The request body is too large."
                : "The request could not be processed.";
            logger.LogWarning("Rejected bad HTTP request with status {StatusCode}: {ExceptionType}.", statusCode, exception.GetType().Name);
        }
        else
        {
            statusCode = StatusCodes.Status500InternalServerError;
            title = "An unexpected error occurred.";

            // Logged as text, not as the exception object: the redaction enricher rewrites properties but never exception
            // objects, so a secret in an exception message would reach the sinks unmasked. Type, message, inner exceptions
            // and stack trace stay available for diagnosis. The route template, never the raw path the caller chose.
            if (logger.IsEnabled(LogLevel.Error))
            {
                LogUnhandled(logger, exception.GetType().FullName, httpContext.Request.Method, EndpointNames.Describe(httpContext), exception.ToString());
            }
        }

        httpContext.Response.StatusCode = statusCode;

        return await problemDetailsService.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            ProblemDetails = new ProblemDetails
            {
                Status = statusCode,
                Title = title,
                Detail = statusCode >= 500
                    ? "The server encountered an unexpected condition. Quote the correlationId when reporting this issue."
                    : null,
                Extensions = { ["errorCode"] = HttpErrorCodes.ForStatus(statusCode) },
            },
            // Exception intentionally not attached: it must never be serialised into the response.
        });
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Unhandled {ExceptionType} while processing {RequestMethod} {Endpoint}: {ExceptionDetail}")]
    private static partial void LogUnhandled(ILogger logger, string? exceptionType, string requestMethod, string endpoint, string exceptionDetail);
}
