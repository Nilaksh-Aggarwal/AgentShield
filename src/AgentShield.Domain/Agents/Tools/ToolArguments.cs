namespace AgentShield.Domain.Agents.Tools;

/// <summary>
/// The validated arguments of one tool action: what a tool receives instead of the JSON the agent sent.
/// </summary>
/// <remarks>
/// Each executable action has its own sealed subtype whose constructor enforces the action's argument schema (for example
/// <see cref="KnowledgeLookupArguments"/>), and the action's argument policy is the only code that builds one from a
/// request. A tool therefore cannot be handed arguments outside its schema: an instance that violates it cannot exist.
/// </remarks>
public abstract record ToolArguments;

/// <summary>
/// Why an argument policy rejected a tool call's arguments. A fixed vocabulary for the audit log; it never carries the
/// rejected value, and the API does not return it.
/// </summary>
public enum ToolArgumentViolation
{
    /// <summary>The arguments are not a JSON object.</summary>
    NotAnObject = 1,

    /// <summary>A required argument is missing.</summary>
    MissingArgument = 2,

    /// <summary>The object has a member the action does not define (names are exact: <c>Query</c> is not <c>query</c>).</summary>
    UnexpectedArgument = 3,

    /// <summary>An argument has the wrong JSON type (including <c>null</c>).</summary>
    WrongType = 4,

    /// <summary>A text argument is empty or only whitespace.</summary>
    Empty = 5,

    /// <summary>A text argument is longer than the action allows.</summary>
    TooLong = 6,

    /// <summary>A text argument contains a control character (line breaks included) or is not well-formed UTF-16.</summary>
    InvalidText = 7,
}
