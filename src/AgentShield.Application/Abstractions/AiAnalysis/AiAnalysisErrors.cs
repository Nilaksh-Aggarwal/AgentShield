using AgentShield.Application.Common.Results;

namespace AgentShield.Application.Abstractions.AiAnalysis;

/// <summary>
/// The failures an <see cref="IAiSecurityAnalyzer"/> reports as results. The codes are the contract between provider
/// adapters and the AI analysis stage, which decides what each failure means for the analysis; a code not listed here
/// is treated as an unclassified failure (the input is held for review).
/// </summary>
/// <remarks>
/// These errors never reach an HTTP response: the stage turns them into an audit status and, where the input may have
/// caused the failure, a finding. Messages are fixed text; adapters must not put provider error bodies in them.
/// </remarks>
public static class AiAnalysisErrors
{
    public const string TimeoutCode = "AiAnalysis.Timeout";
    public const string UnavailableCode = "AiAnalysis.Unavailable";
    public const string RateLimitedCode = "AiAnalysis.RateLimited";
    public const string NetworkFailureCode = "AiAnalysis.NetworkFailure";
    public const string MalformedResponseCode = "AiAnalysis.MalformedResponse";
    public const string RefusedCode = "AiAnalysis.Refused";
    public const string RequestRejectedCode = "AiAnalysis.RequestRejected";

    /// <summary>The provider's own timeout expired (the stage enforces its own timeout as well).</summary>
    public static Error Timeout() =>
        Error.ExternalDependency(TimeoutCode, "The AI provider did not answer in time.");

    /// <summary>The provider reported an outage (e.g. HTTP 500/502/503, or an open circuit breaker).</summary>
    public static Error Unavailable() =>
        Error.ExternalDependency(UnavailableCode, "The AI provider is unavailable.");

    /// <summary>The provider rejected the call because of a rate or quota limit (e.g. HTTP 429).</summary>
    public static Error RateLimited() =>
        Error.ExternalDependency(RateLimitedCode, "The AI provider rate limit was reached.");

    /// <summary>The provider could not be reached (connection refused/reset, DNS or TLS failure).</summary>
    public static Error NetworkFailure() =>
        Error.ExternalDependency(NetworkFailureCode, "The AI provider could not be reached.");

    /// <summary>The answer was not the expected structured output (not JSON, too large, unknown or duplicate fields).</summary>
    public static Error MalformedResponse() =>
        Error.ExternalDependency(MalformedResponseCode, "The AI provider returned a malformed response.");

    /// <summary>The model declined to analyse the content (e.g. a safety refusal instead of structured output).</summary>
    public static Error Refused() =>
        Error.ExternalDependency(RefusedCode, "The AI model declined to analyse the content.");

    /// <summary>
    /// The provider answered and rejected the request itself: e.g. HTTP 400 or 413, which the input may have caused, or a
    /// configuration fault such as an invalid key, a missing permission or an unknown model (e.g. HTTP 401, 403, 404).
    /// Neither is an outage or a rate limit, so it never opens the circuit; the stage does not assume the input is
    /// innocent and treats it as an unclassified failure (Review).
    /// </summary>
    public static Error RequestRejected() =>
        Error.ExternalDependency(RequestRejectedCode, "The AI provider rejected the analysis request.");
}
