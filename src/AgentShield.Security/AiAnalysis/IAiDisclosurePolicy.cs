using AgentShield.Application.Abstractions.Security;

namespace AgentShield.Security.AiAnalysis;

/// <summary>
/// Decides what of an input may leave the process for an external AI provider, and in what form. The extension point
/// for privacy controls before disclosure: secret redaction and the size limit today; PII handling, per-provider rules
/// and data-retention constraints later (docs/security/ai-analysis.md, "Privacy").
/// </summary>
/// <remarks>
/// Must be deterministic and bounded. It may withhold content but never truncate it: a truncated input would let an
/// attacker put the payload just past the cut. Withheld content holds the input for review.
/// </remarks>
internal interface IAiDisclosurePolicy
{
    AiDisclosure Prepare(NormalizedInput input);
}

/// <summary>The content that may be sent to the provider, or <see cref="Withheld"/>.</summary>
internal sealed record AiDisclosure
{
    private AiDisclosure(string? content) => Content = content;

    /// <summary>Nothing may be sent.</summary>
    public static AiDisclosure Withheld { get; } = new(content: null);

    /// <summary>The content to send; <see langword="null"/> when withheld.</summary>
    public string? Content { get; }

    public static AiDisclosure Disclose(string content)
    {
        ArgumentNullException.ThrowIfNull(content);
        return new AiDisclosure(content);
    }
}
