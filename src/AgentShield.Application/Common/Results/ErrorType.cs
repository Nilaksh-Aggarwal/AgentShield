namespace AgentShield.Application.Common.Results;

/// <summary>
/// Category of an expected application failure. Framework-independent: the API layer decides how
/// each category is represented over HTTP.
/// </summary>
public enum ErrorType
{
    /// <summary>The request is well-formed but semantically invalid.</summary>
    Validation,

    /// <summary>The requested resource does not exist.</summary>
    NotFound,

    /// <summary>The request conflicts with the current state of a resource.</summary>
    Conflict,

    /// <summary>The caller is not authenticated.</summary>
    Unauthorized,

    /// <summary>The caller is authenticated but not permitted to perform the operation.</summary>
    Forbidden,

    /// <summary>A business/domain rule prevents the operation.</summary>
    BusinessRule,

    /// <summary>An external dependency (LLM provider, remote API, ...) failed or returned an invalid response.</summary>
    ExternalDependency,

    /// <summary>An unexpected failure that was nonetheless captured as a result rather than thrown.</summary>
    Unexpected,
}
