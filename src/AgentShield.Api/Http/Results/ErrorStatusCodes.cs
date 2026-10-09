using AgentShield.Application.Common.Results;

namespace AgentShield.Api.Http.Results;

/// <summary>The single place where application error categories become HTTP status codes.</summary>
public static class ErrorStatusCodes
{
    public static int For(ErrorType type) => type switch
    {
        ErrorType.Validation => StatusCodes.Status422UnprocessableEntity,
        ErrorType.BusinessRule => StatusCodes.Status422UnprocessableEntity,
        ErrorType.NotFound => StatusCodes.Status404NotFound,
        ErrorType.Conflict => StatusCodes.Status409Conflict,
        ErrorType.Unauthorized => StatusCodes.Status401Unauthorized,
        ErrorType.Forbidden => StatusCodes.Status403Forbidden,
        ErrorType.ExternalDependency => StatusCodes.Status502BadGateway,
        ErrorType.Unexpected => StatusCodes.Status500InternalServerError,
        _ => StatusCodes.Status500InternalServerError,
    };
}
