namespace AgentShield.Domain.SecurityEvents;

/// <summary>
/// How the AI-assisted analysis stage ended for one input. Audit data: logged with the security event, never returned
/// to API clients (it would tell an attacker whether they stalled or confused the analyser).
/// </summary>
/// <remarks>
/// What each status does to the decision is defined by the Security layer's failure handling
/// (docs/security/ai-analysis.md): every failure of an expected AI analysis, provider-side ones included, holds the input
/// for review; nothing falls back to the deterministic pipeline alone.
/// </remarks>
public enum AiAnalysisStatus
{
    /// <summary>No AI provider is configured; the deterministic pipeline decided alone.</summary>
    Disabled = 1,

    /// <summary>The provider answered within the contract; its validated findings joined the deterministic ones.</summary>
    Completed = 2,

    /// <summary>The input was not sent: the disclosure policy withheld it (e.g. too large to send without truncating).</summary>
    ContentWithheld = 3,

    /// <summary>The provider did not answer within the timeout.</summary>
    TimedOut = 4,

    /// <summary>The provider reported that it is unavailable (outage, maintenance, open circuit).</summary>
    Unavailable = 5,

    /// <summary>The provider rejected the call because a rate or quota limit was reached.</summary>
    RateLimited = 6,

    /// <summary>The provider could not be reached (connection, DNS or TLS failure).</summary>
    NetworkFailure = 7,

    /// <summary>The provider's answer was not the expected structured output (not JSON, too large, unknown fields).</summary>
    MalformedResponse = 8,

    /// <summary>The answer was well-formed but broke the output contract (unknown values, out-of-range confidence, ...).</summary>
    InvalidResponse = 9,

    /// <summary>The model declined to analyse the input.</summary>
    Refused = 10,

    /// <summary>The provider adapter reported a failure it did not classify.</summary>
    UnclassifiedFailure = 11,

    /// <summary>
    /// AgentShield's own AI capacity budget (requests per minute or per day, globally or for the client, or concurrent
    /// calls) refused the call. The input was not sent.
    /// </summary>
    CapacityExceeded = 12,

    /// <summary>
    /// The provider was not called because the deterministic decision was already Block, which AI findings (they only
    /// add) cannot change. No AI capacity was used.
    /// </summary>
    NotNeeded = 13,

    /// <summary>
    /// The provider was not called because the AI circuit breaker is open (repeated provider availability failures), or
    /// because its single half-open probe call is in flight. The input was not sent.
    /// </summary>
    CircuitOpen = 14,
}
