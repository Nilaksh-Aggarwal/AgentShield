namespace AgentShield.Api.Http.Errors;

/// <summary>
/// Default <c>errorCode</c> for Problem Details produced by the framework (routing, model binding,
/// status-code pages, unhandled exceptions) rather than by an application <c>Error</c>.
/// </summary>
public static class HttpErrorCodes
{
    public const string MalformedRequest = "Request.Malformed";
    public const string ValidationFailed = "Validation.Failed";
    public const string Unexpected = "Server.Unexpected";

    public static string ForStatus(int statusCode) => statusCode switch
    {
        StatusCodes.Status400BadRequest => MalformedRequest,
        StatusCodes.Status401Unauthorized => "Auth.Unauthenticated",
        StatusCodes.Status403Forbidden => "Auth.Forbidden",
        StatusCodes.Status404NotFound => "Resource.NotFound",
        StatusCodes.Status405MethodNotAllowed => "Request.MethodNotAllowed",
        StatusCodes.Status406NotAcceptable => "Request.NotAcceptable",
        StatusCodes.Status409Conflict => "Resource.Conflict",
        StatusCodes.Status413PayloadTooLarge => "Request.TooLarge",
        StatusCodes.Status415UnsupportedMediaType => "Request.UnsupportedMediaType",
        StatusCodes.Status422UnprocessableEntity => ValidationFailed,
        StatusCodes.Status429TooManyRequests => "Request.RateLimited",
        StatusCodes.Status500InternalServerError => Unexpected,
        StatusCodes.Status502BadGateway => "Dependency.Failed",
        StatusCodes.Status503ServiceUnavailable => "Server.Unavailable",
        StatusCodes.Status504GatewayTimeout => "Dependency.Timeout",
        >= 500 => "Server.Error",
        _ => "Request.Error",
    };
}
