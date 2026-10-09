namespace AgentShield.Application.Activity;

/// <summary>
/// What AI-assisted analysis contributed to one security event, as far as the activity history shows it.
/// </summary>
/// <remarks>
/// Deliberately coarser than the audit log's <see cref="Domain.SecurityEvents.AiAnalysisStatus"/>: every way an expected
/// AI analysis can fail (timeout, outage, rate limit, open circuit, exhausted capacity, invalid or refused answer) is
/// <see cref="Incomplete"/>. Which one it was stays in the audit log, so the history cannot be used to learn whether an
/// input stalled, confused or exhausted the analyser. An incomplete analysis already shows in the decision itself
/// (the <c>InconclusiveAnalysis.AiAnalysisIncomplete</c> finding holds the input for review).
/// </remarks>
public enum ActivityAiStatus
{
    /// <summary>No AI provider is configured; the deterministic pipeline decided alone.</summary>
    Disabled = 1,

    /// <summary>The AI analysis completed; any findings it added joined the deterministic ones.</summary>
    Completed = 2,

    /// <summary>The AI was not asked because the deterministic decision was already Block.</summary>
    NotNeeded = 3,

    /// <summary>An expected AI analysis did not complete, so the input was held for review.</summary>
    Incomplete = 4,
}
