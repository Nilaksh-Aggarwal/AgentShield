using AgentShield.Security.Detection.Obfuscation;

namespace AgentShield.Security.AiAnalysis;

/// <summary>
/// Hard bounds of the AI-assisted analysis stage. Constants, like <see cref="ObfuscationLimits"/>: changing one is a
/// reviewed code change (docs/security/ai-analysis.md explains each value).
/// </summary>
internal static class AiAnalysisLimits
{
    /// <summary>
    /// Maximum time from sending the request to having the answer. The deterministic pipeline takes milliseconds; a
    /// short structured classification call to a hosted model typically answers in well under two seconds. Three
    /// seconds bounds the firewall's added latency while leaving headroom for normal provider variance. A call that
    /// exceeds it is abandoned (even if the adapter ignores cancellation) and the input is held for review.
    /// </summary>
    public static readonly TimeSpan Timeout = TimeSpan.FromSeconds(3);

    /// <summary>
    /// Largest content (UTF-16 code units, after normalisation and redaction) sent to a provider: the same bound as
    /// <see cref="ObfuscationLimits.MaxViewLength"/>, twice the API input limit. Only pathological NFKC expansion
    /// exceeds it. Content is never truncated (the payload would sit just past the cut); it is withheld and the input
    /// is held for review.
    /// </summary>
    public const int MaxContentLength = ObfuscationLimits.MaxViewLength;

    /// <summary>
    /// Most findings accepted in one response. The catalogue has four codes, so a legitimate answer needs far fewer;
    /// more is treated as a broken contract, not trimmed.
    /// </summary>
    public const int MaxFindings = 16;

    /// <summary>Longest model-written description accepted (it is validated, then discarded).</summary>
    public const int MaxDescriptionLength = 500;
}
