using System.Collections.Frozen;
using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Common.Results;
using AgentShield.Domain.Threats;

namespace AgentShield.Security.AiAnalysis;

/// <summary>
/// Validates untrusted AI output against the output contract and maps it to <see cref="ThreatFinding"/>s. Pure and
/// deterministic. All or nothing: one violation rejects the whole response, because a response that breaks the
/// contract anywhere cannot be trusted anywhere (and partial acceptance would let manipulated output pick which of its
/// findings survive).
/// </summary>
/// <remarks>
/// <para>Rules, each identified in the error's <see cref="ViolationKey"/> metadata:</para>
/// <list type="bullet">
/// <item><c>findings</c> is present and has at most <see cref="AiAnalysisLimits.MaxFindings"/> entries, none null.</item>
/// <item><c>category</c> is the exact name of an attack category in the catalogue (no numbers, other casings or
/// <c>InconclusiveAnalysis</c>).</item>
/// <item><c>code</c> is a catalogue code, reported under the category it belongs to.</item>
/// <item><c>severity</c> is the exact name of a <see cref="ThreatSeverity"/>.</item>
/// <item><c>confidence</c> is a finite number from 0 to 1.</item>
/// <item><c>description</c> is present, not blank and at most <see cref="AiAnalysisLimits.MaxDescriptionLength"/>
/// characters. It is then discarded: the finding's description comes from the catalogue.</item>
/// </list>
/// <para>Syntactic rules (valid JSON, size, unknown or duplicate fields, number and string types) belong to the
/// provider adapter's parser and surface as <see cref="AiAnalysisErrors.MalformedResponseCode"/>.</para>
/// </remarks>
internal static class AiResponseValidator
{
    public const string InvalidResponseCode = "AiAnalysis.InvalidResponse";

    /// <summary>Metadata key naming the violated rule (e.g. <c>confidence.outOfRange</c>). Fixed text, safe to log.</summary>
    public const string ViolationKey = "violation";

    private static readonly FrozenDictionary<string, ThreatSeverity> Severities =
        Enum.GetValues<ThreatSeverity>().ToFrozenDictionary(severity => severity.ToString(), StringComparer.Ordinal);

    private static readonly FrozenDictionary<string, ThreatCategory> AttackCategories =
        AiFindingCatalog.Entries.Values
            .Select(entry => entry.Category)
            .Distinct()
            .ToFrozenDictionary(category => category.ToString(), StringComparer.Ordinal);

    /// <param name="output">The provider's raw structured output.</param>
    /// <param name="provider">Provider identity, recorded in each finding's evidence rule ID (<c>AI/{provider}</c>).</param>
    public static Result<IReadOnlyList<ThreatFinding>> Validate(AiAnalysisOutput output, string provider)
    {
        ArgumentNullException.ThrowIfNull(output);
        ArgumentException.ThrowIfNullOrWhiteSpace(provider);

        if (output.Findings is not { } candidates)
        {
            return Invalid("findings.required");
        }

        if (candidates.Count > AiAnalysisLimits.MaxFindings)
        {
            return Invalid("findings.tooMany");
        }

        var evidence = new FindingEvidence(AiFindingCatalog.Detector, $"AI/{provider}", 1);
        var findings = new List<ThreatFinding>(candidates.Count);
        foreach (var candidate in candidates)
        {
            var violation = Check(candidate, out var entry, out var severity);
            if (violation is not null)
            {
                return Invalid(violation);
            }

            findings.Add(new ThreatFinding(entry!.Code, entry.Category, severity, candidate!.Confidence!.Value, entry.Description, evidence));
        }

        return findings.AsReadOnly();
    }

    private static string? Check(AiFindingCandidate? candidate, out AiFindingCatalog.Entry? entry, out ThreatSeverity severity)
    {
        entry = null;
        severity = default;

        if (candidate is null)
        {
            return "finding.required";
        }

        if (string.IsNullOrEmpty(candidate.Category))
        {
            return "category.required";
        }

        if (!AttackCategories.TryGetValue(candidate.Category, out var category))
        {
            return "category.unknown";
        }

        if (string.IsNullOrEmpty(candidate.Code))
        {
            return "code.required";
        }

        if (!AiFindingCatalog.Entries.TryGetValue(candidate.Code, out entry))
        {
            return "code.unknown";
        }

        if (entry.Category != category)
        {
            return "code.categoryMismatch";
        }

        if (string.IsNullOrEmpty(candidate.Severity))
        {
            return "severity.required";
        }

        if (!Severities.TryGetValue(candidate.Severity, out severity))
        {
            return "severity.unknown";
        }

        if (candidate.Confidence is not { } confidence)
        {
            return "confidence.required";
        }

        // Also rejects NaN and infinities, for which the range comparison alone is not enough.
        if (!double.IsFinite(confidence) || confidence is < 0.0 or > 1.0)
        {
            return "confidence.outOfRange";
        }

        if (string.IsNullOrWhiteSpace(candidate.Description))
        {
            return "description.required";
        }

        return candidate.Description.Length > AiAnalysisLimits.MaxDescriptionLength ? "description.tooLong" : null;
    }

    private static Error Invalid(string violation) =>
        Error.ExternalDependency(InvalidResponseCode, "The AI provider's response broke the output contract.")
            .WithMetadata(ViolationKey, violation);
}
