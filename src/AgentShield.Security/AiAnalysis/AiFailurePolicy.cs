using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Security.AiAnalysis;

/// <summary>What an AI analysis failure does to the analysis. Nothing here decides; the policy engine still does.</summary>
internal enum AiFailureHandling
{
    /// <summary>Add <see cref="AiFindingCatalog.IncompleteCode"/> (Medium), which the policy maps to at least Review.</summary>
    Review = 2,
}

/// <summary>
/// The failure table of AI-assisted analysis (docs/security/ai-analysis.md, "Failure behaviour").
/// </summary>
/// <remarks>
/// <para>The rule since Milestone 6 step 2 (ADR 0016): <b>when AI analysis was expected but did not complete, the input
/// is held for review; it never falls back to the deterministic decision alone.</b> The deterministic rules miss
/// attacks (paraphrases, other languages) that only the AI detects. Any failure that fell back to "deterministic only"
/// would be a switch an attacker could flip to let such an attack through as Allow: by crafting content (timeouts,
/// refusals, broken output), by spending the AI budget, or by pushing the shared provider quota into 429s.</para>
/// <para>Provider availability failures (<see cref="AiProviderAvailability.IsAvailabilityFailure"/>) used to fall back
/// to the deterministic decision (ADR 0012). The circuit breaker now bounds what an outage costs: after a few failures
/// it stops calling the provider (Review at once, no 3 s wait) and probes it once per open period, so an outage means
/// Review for inputs the deterministic pipeline would allow, and a deterministic Block still blocks without AI.</para>
/// <para>Not in the table: an exception from the adapter or stage is a bug and fails the request closed (500, no
/// decision, as for detectors, ADR 0010); caller cancellation stops the analysis without a decision. Nothing is retried
/// (docs/security/ai-analysis.md explains why).</para>
/// </remarks>
internal static class AiFailurePolicy
{
    public static AiFailureHandling For(AiAnalysisStatus status) => status switch
    {
        // The provider could not serve the call (429, outage, network, no answer in time). Also counted by the circuit
        // breaker. Timeouts can also be content-induced (input crafted to stall the model).
        AiAnalysisStatus.Unavailable
            or AiAnalysisStatus.RateLimited
            or AiAnalysisStatus.NetworkFailure
            or AiAnalysisStatus.TimedOut => AiFailureHandling.Review,

        // The circuit breaker did not let the call through (open, or its one probe is in flight).
        AiAnalysisStatus.CircuitOpen => AiFailureHandling.Review,

        // AgentShield's own AI budget refused the call. Callers' traffic causes this (a client that spends its share, or
        // concurrent calls): an attacker must not be able to exhaust the budget first and then send attacks only the AI
        // detects. Per-client shares keep one client's exhaustion from reaching the others.
        AiAnalysisStatus.CapacityExceeded => AiFailureHandling.Review,

        // The content can cause each of these: oversized or unredactable input, prompt injection against the analyser
        // that breaks its output format, a safety refusal triggered by the content, or an adapter failure nobody
        // classified.
        AiAnalysisStatus.ContentWithheld
            or AiAnalysisStatus.MalformedResponse
            or AiAnalysisStatus.InvalidResponse
            or AiAnalysisStatus.Refused
            or AiAnalysisStatus.UnclassifiedFailure => AiFailureHandling.Review,

        _ => throw new ArgumentOutOfRangeException(nameof(status), status, "Not an AI analysis failure."),
    };
}
