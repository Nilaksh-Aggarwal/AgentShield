using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Security.Redaction;

namespace AgentShield.Security.AiAnalysis;

/// <summary>
/// The initial disclosure policy: send the normalised input with secrets masked, unless it is too large to send whole.
/// </summary>
/// <remarks>
/// <list type="number">
/// <item>Normalised text, not the original: invisible characters are already removed and compatibility forms folded, so
/// the model sees what the detectors saw.</item>
/// <item>Longer than <see cref="AiAnalysisLimits.MaxContentLength"/> → withheld (checked before redaction to bound its
/// work, and after, because masking can lengthen text).</item>
/// <item>Bearer tokens, JWTs, credential assignments and well-known API key formats are replaced by
/// <see cref="SensitiveDataRedactor.Mask"/> (the rules used for log redaction). The provider never needs a secret's
/// value to judge intent. If redaction cannot finish in time, the content is withheld rather than sent unredacted.</item>
/// </list>
/// The deterministic detectors always analyse the full, unredacted input; this only limits what leaves the process.
/// </remarks>
internal sealed class RedactingAiDisclosurePolicy : IAiDisclosurePolicy, ISingletonService
{
    public AiDisclosure Prepare(NormalizedInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        if (input.Normalized.Length > AiAnalysisLimits.MaxContentLength
            || !SensitiveDataRedactor.TryRedactValue(input.Normalized, out var redacted)
            || redacted.Length > AiAnalysisLimits.MaxContentLength)
        {
            return AiDisclosure.Withheld;
        }

        return AiDisclosure.Disclose(redacted);
    }
}
