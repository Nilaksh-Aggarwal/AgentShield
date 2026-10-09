using System.Collections.Frozen;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Domain.Threats;

namespace AgentShield.Security.AiAnalysis;

/// <summary>
/// The closed set of findings AI-assisted analysis may produce. The model chooses a code; everything a client sees
/// (code, category, description) comes from this catalogue, never from model-written text.
/// </summary>
/// <remarks>
/// <para>AI codes are distinct from every deterministic detector's codes (<c>*.AiDetected</c>), so the finding aggregator
/// (key: category + code) never fuses an AI finding into a deterministic one. AI output therefore cannot lower the
/// severity, replace the description or take over the evidence of a deterministic finding; it can only add findings.
/// Duplicate AI findings with the same code are fused like any other duplicates.</para>
/// <para><see cref="ThreatCategory.InconclusiveAnalysis"/> is not in the catalogue: only the stage itself raises it,
/// after a failure. A model that claims it breaks the contract.</para>
/// </remarks>
internal static class AiFindingCatalog
{
    /// <summary>Detector identity recorded in the evidence of every AI finding (audit data, not returned).</summary>
    public const string Detector = "AiAnalysis";

    public const string InstructionOverride = "InstructionOverride.AiDetected";
    public const string RoleManipulation = "RoleManipulation.AiDetected";
    public const string SecretExtraction = "SecretExtraction.AiDetected";
    public const string Obfuscation = "Obfuscation.AiDetected";

    /// <summary>Holds an input for review when AI analysis failed in a way the input may have caused.</summary>
    public const string IncompleteCode = "InconclusiveAnalysis.AiAnalysisIncomplete";

    /// <summary>Severity of <see cref="IncompleteCode"/>: Medium, which the policy maps to Review.</summary>
    public const ThreatSeverity IncompleteSeverity = ThreatSeverity.Medium;

    /// <summary>Confidence of <see cref="IncompleteCode"/>: a failure says nothing either way about intent.</summary>
    public const double IncompleteConfidence = 0.5;

    public static FrozenDictionary<string, Entry> Entries { get; } = new Entry[]
    {
        new(InstructionOverride, ThreatCategory.InstructionOverride,
            "AI-assisted analysis indicates an attempt to override or replace the model's instructions."),
        new(RoleManipulation, ThreatCategory.RoleManipulation,
            "AI-assisted analysis indicates an attempt to change the model's role or to impersonate a trusted speaker."),
        new(SecretExtraction, ThreatCategory.SecretExtraction,
            "AI-assisted analysis indicates an attempt to extract instructions, credentials or other protected data."),
        new(Obfuscation, ThreatCategory.Obfuscation,
            "AI-assisted analysis indicates a manipulation attempt hidden by encoding or disguise."),
    }.ToFrozenDictionary(entry => entry.Code, StringComparer.Ordinal);

    /// <summary>
    /// The finding that holds an input for review after <paramref name="status"/>. One client-visible code for every
    /// failure kind, so a client cannot tell whether it stalled, confused or triggered a refusal from the analyser; the
    /// kind is in the evidence rule ID (<c>AI-FAIL/TimedOut</c>, <c>AI-FAIL/InvalidResponse/confidence.outOfRange</c>),
    /// which is logged but not returned.
    /// </summary>
    /// <param name="status">The failure.</param>
    /// <param name="violation">For an invalid response, the violated output rule (fixed text from the validator).</param>
    public static ThreatFinding Incomplete(AiAnalysisStatus status, string? violation = null) => new(
        IncompleteCode,
        ThreatCategory.InconclusiveAnalysis,
        IncompleteSeverity,
        IncompleteConfidence,
        "AI-assisted analysis could not assess this input, so it is held for review.",
        new FindingEvidence(Detector, violation is null ? $"AI-FAIL/{status}" : $"AI-FAIL/{status}/{violation}", 1));

    /// <summary>A finding the AI may report.</summary>
    /// <param name="Code">Stable code (<c>Category.AiDetected</c>).</param>
    /// <param name="Category">The only category this code may be reported under.</param>
    /// <param name="Description">Fixed, client-safe text shown instead of the model's own description.</param>
    public sealed record Entry(string Code, ThreatCategory Category, string Description);
}
