using System.Text.RegularExpressions;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Domain.Threats;

namespace AgentShield.Security.Detection.Obfuscation;

/// <summary>
/// Finds manipulation attempts hidden by encoding or character-level disguise: it builds bounded, transformed views of
/// the normalised input, re-applies every pattern rule to them, and reports rules that match only once the disguise is
/// undone.
/// </summary>
/// <remarks>
/// <para>Pipeline per input (all deterministic, limits in <see cref="ObfuscationLimits"/>):</para>
/// <list type="number">
/// <item>Candidates: a decoder or unmasking step only produces a view when the text contains something it can
/// transform (a Base64 run that decodes to text, a percent escape, an HTML reference, a look-alike letter, a run of
/// hidden characters, …).</item>
/// <item>Views: text hidden in invisible characters, read from the <i>original</i> input because normalisation deletes
/// those characters (<see cref="HiddenCharacterDecoding"/>, two readings); unmasked text (<see cref="CharacterUnmasking"/>,
/// two readings of the digit 1); then decoded text (<see cref="ContentDecoders"/>) up to
/// <see cref="ObfuscationLimits.MaxDecodingDepth"/> layers. Each view is normalised like the input.</item>
/// <item>Inspection: every rule of every <see cref="IPatternRuleSource"/> plus the compact rules below.</item>
/// <item>Finding: only for a rule that matches the view <i>more often than the text it was derived from</i>. A decoder
/// on its own never raises a finding, benign encoded content (images, hashes, JWTs, URLs) raises none, and an attack
/// that is already visible in plain text is left to the plain detectors instead of being reported twice.</item>
/// </list>
/// <para>A finding's severity is the inner rule's severity raised to at least <see cref="ThreatSeverity.High"/>:
/// hiding a manipulation attempt is itself evidence of intent. Confidence is the inner rule's confidence times a
/// heuristic factor for the transformation (1.0 for exact decoding, hidden characters included, 0.9 for lossy
/// unmasking). Evidence records the transformation chain and inner rule (<c>OB-B64/IO-001</c>, <c>OB-PCT+B64/SE-001</c>,
/// <c>OB-MASK/RM-002</c>, <c>OB-HID/IO-001</c>), never the decoded content.</para>
/// <para>This detector is not an <see cref="IPatternRuleSource"/> and never runs on its own output, so there is no
/// recursion.</para>
/// </remarks>
internal sealed partial class ObfuscationDetector : IThreatDetector, ISingletonService
{
    public const string DetectorId = "Obfuscation";

    public const string EncodedThreatCode = "Obfuscation.EncodedThreat";
    public const string MaskedThreatCode = "Obfuscation.MaskedThreat";
    public const string UninspectableContentCode = "Obfuscation.UninspectableContent";

    public const string EncodedThreatDescription =
        "Potentially malicious content was detected after bounded decoding of encoded text.";

    public const string MaskedThreatDescription =
        "Potentially malicious content was detected after undoing character-level obfuscation.";

    public const string UninspectableContentDescription =
        "Encoded or obfuscated content exceeded the inspection limits and could not be fully analysed.";

    /// <summary>Evidence rule ID of <see cref="UninspectableContentCode"/>.</summary>
    public const string LimitRuleId = "OB-LIMIT";

    private const double DecodingConfidenceFactor = 1.0;
    private const double UnmaskingConfidenceFactor = 0.9;
    private const double UninspectableConfidence = 0.5;

    private static readonly Decoder[] Decoders =
    [
        new("B64", ContentDecoders.DecodeBase64Segments),
        new("PCT", ContentDecoders.DecodePercentEncoding),
        new("HTML", ContentDecoders.DecodeHtmlEntities),
    ];

    /// <summary>
    /// Rules for words fused by unmasking spaced-out text (<c>i g n o r e p r e v i o u s …</c> becomes
    /// <c>ignoreprevious…</c>), which the word-based rules cannot match. Only ever reported through a view, so they
    /// never fire on plain text.
    /// </summary>
    private static readonly PatternRule[] CompactRuleSet =
    [
        new(
            "OB-C01",
            "InstructionOverride.IgnorePrevious",
            ThreatSeverity.High,
            0.8,
            "Asks the model to ignore or override its previous instructions.",
            CompactIgnorePreviousPattern()),
        new(
            "OB-C02",
            "SecretExtraction.SystemPromptDisclosure",
            ThreatSeverity.High,
            0.8,
            "Asks the model to disclose its system prompt or hidden instructions.",
            CompactPromptDisclosurePattern()),
        new(
            "OB-C03",
            "RoleManipulation.UnrestrictedPersona",
            ThreatSeverity.High,
            0.8,
            "Asks the model to adopt a persona without its safety rules.",
            CompactPersonaPattern()),
    ];

    private readonly IInputNormalizer _normalizer;
    private readonly PatternRule[] _rules;

    public ObfuscationDetector(IInputNormalizer normalizer, IEnumerable<IPatternRuleSource> ruleSources)
    {
        ArgumentNullException.ThrowIfNull(normalizer);
        ArgumentNullException.ThrowIfNull(ruleSources);

        _normalizer = normalizer;
        _rules =
        [
            .. ruleSources
                .SelectMany(source => source.Rules)
                .Concat(CompactRuleSet)
                .DistinctBy(rule => rule.Id, StringComparer.Ordinal)
                .OrderBy(rule => rule.Id, StringComparer.Ordinal),
        ];
    }

    /// <summary>The compact rules this detector adds, for tests and documentation.</summary>
    public static IReadOnlyList<PatternRule> CompactRules => CompactRuleSet;

    /// <summary>Every rule applied to views, in evaluation order (by rule ID).</summary>
    public IReadOnlyList<PatternRule> InspectionRules => _rules;

    public IReadOnlyList<ThreatFinding> Detect(NormalizedInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        // Not only when the normalised text is non-empty: an input made of nothing but hidden characters normalises to
        // empty text, and what it hides exists only in the original.
        return input.Original.Length == 0 ? [] : new Analysis(this, input.Normalized, input.Original).Run();
    }

    private int[] CountMatches(string text)
    {
        var counts = new int[_rules.Length];
        for (var i = 0; i < _rules.Length; i++)
        {
            // A RegexMatchTimeoutException is not caught: the analysis fails closed, as in PatternThreatDetector.
            counts[i] = _rules[i].Pattern.Count(text);
        }

        return counts;
    }

    // verb … optional fillers … previous/prior/… … instructions/prompt/…, without separators.
    [GeneratedRegex(
        @"(?:ignore|disregard|forget|bypass|override)(?:all|the|your|any|of|my){0,3}(?:previous|prior|preceding|above|earlier|original|initial|system|developer)(?:instructions?|prompts?|rules|guidelines|directives|directions|context)",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex CompactIgnorePreviousPattern();

    [GeneratedRegex(
        @"(?:reveal|show|print|display|output|repeat|leak|dump|tellme|giveme)(?:me)?(?:your|the)(?:system|initial|original|hidden|secret|internal)(?:prompts?|instructions|rules)",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex CompactPromptDisclosurePattern();

    [GeneratedRegex(
        @"youarenow(?:dan|unrestricted|unfiltered|uncensored|jailbroken)|(?:developer|god|dan|jailbreak)mode(?:enabled|activated)|doanythingnow",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex CompactPersonaPattern();

    private sealed record Decoder(string Id, Func<string, string?> Decode);

    private sealed record View(string Text, string Chain, int[] Counts);

    /// <summary>State of one <see cref="Detect"/> call. Never stored; views are dropped when the call returns.</summary>
    /// <param name="detector">The detector whose rules are applied.</param>
    /// <param name="text">The normalised input: the baseline every view is compared with, and the source of most views.</param>
    /// <param name="original">The input as received: the only source of the hidden-character views.</param>
    private sealed class Analysis(ObfuscationDetector detector, string text, string original)
    {
        private readonly List<ThreatFinding> _findings = [];
        private int[]? _baselineCounts;
        private int _viewsLeft = ObfuscationLimits.MaxViews;
        private bool _limitReached;

        private int[] BaselineCounts => _baselineCounts ??= detector.CountMatches(text);

        public List<ThreatFinding> Run()
        {
            InspectHiddenViews();
            InspectUnmaskedViews();
            InspectDecodedViews();

            if (_limitReached)
            {
                _findings.Add(new ThreatFinding(
                    UninspectableContentCode,
                    ThreatCategory.Obfuscation,
                    ThreatSeverity.Medium,
                    UninspectableConfidence,
                    UninspectableContentDescription,
                    new FindingEvidence(DetectorId, LimitRuleId, 1)));
            }

            return _findings;
        }

        // Both readings of hidden text are one technique, as for the digit 1 below: per rule, the reading that reveals
        // more matches counts. Compared with the normalised input, which is exactly the text without the hidden runs.
        private void InspectHiddenViews()
        {
            if (HiddenCharacterDecoding.Reveal(original) is not { } hidden)
            {
                return;
            }

            int[]? counts = null;
            foreach (var reading in (ReadOnlySpan<string?>)[hidden.InPlace, hidden.Alone])
            {
                if (reading is null || TryPrepareView(reading) is not { } view)
                {
                    continue;
                }

                var viewCounts = detector.CountMatches(view);
                counts = counts is null ? viewCounts : [.. counts.Zip(viewCounts, Math.Max)];
            }

            if (counts is not null)
            {
                Report("HID", counts, BaselineCounts, MaskedThreatCode, MaskedThreatDescription, DecodingConfidenceFactor);
            }
        }

        // Both readings of the digit 1 are one technique: per rule, the view that reveals more matches counts.
        private void InspectUnmaskedViews()
        {
            int[]? counts = null;
            string? previous = null;
            foreach (var digitOneAs in (ReadOnlySpan<char>)['i', 'l'])
            {
                var unmasked = CharacterUnmasking.Unmask(text, digitOneAs);
                if (unmasked is null || string.Equals(unmasked, previous, StringComparison.Ordinal)
                    || TryPrepareView(unmasked) is not { } view)
                {
                    continue;
                }

                previous = unmasked;
                var viewCounts = detector.CountMatches(view);
                counts = counts is null ? viewCounts : [.. counts.Zip(viewCounts, Math.Max)];
            }

            if (counts is not null)
            {
                Report("MASK", counts, BaselineCounts, MaskedThreatCode, MaskedThreatDescription, UnmaskingConfidenceFactor);
            }
        }

        private void InspectDecodedViews()
        {
            // Matches each decoder revealed on its own (depth 1), so deeper views are not credited with them again.
            var revealedAlone = new Dictionary<string, int[]>(StringComparer.Ordinal);

            List<View> parents = [new View(text, string.Empty, [])];
            for (var depth = 1; depth <= ObfuscationLimits.MaxDecodingDepth && parents.Count > 0; depth++)
            {
                var children = new List<View>();
                foreach (var parent in parents)
                {
                    foreach (var decoder in Decoders)
                    {
                        if (decoder.Decode(parent.Text) is not { } decoded || TryPrepareView(decoded) is not { } view)
                        {
                            continue;
                        }

                        var counts = detector.CountMatches(view);
                        string chain;
                        int[] expected;
                        if (depth == 1)
                        {
                            chain = decoder.Id;
                            expected = BaselineCounts;
                            revealedAlone[decoder.Id] = Subtract(counts, BaselineCounts);
                        }
                        else
                        {
                            // e.g. Base64 decoded first still contains a percent-encoded attack that percent decoding
                            // alone already revealed: that is not nested encoding.
                            chain = parent.Chain + "+" + decoder.Id;
                            expected = revealedAlone.TryGetValue(decoder.Id, out var alone) ? Add(parent.Counts, alone) : parent.Counts;
                        }

                        Report(chain, counts, expected, EncodedThreatCode, EncodedThreatDescription, DecodingConfidenceFactor);
                        children.Add(new View(view, chain, counts));
                    }
                }

                parents = children;
            }
        }

        private static int[] Subtract(int[] left, int[] right) => [.. left.Zip(right, (l, r) => Math.Max(0, l - r))];

        private static int[] Add(int[] left, int[] right) => [.. left.Zip(right, (l, r) => l + r)];

        // Normalises a view like the input and enforces the view limits. Oversized content is flagged, never cut.
        private string? TryPrepareView(string transformed)
        {
            if (_viewsLeft == 0 || transformed.Length > ObfuscationLimits.MaxViewLength)
            {
                _limitReached = true;
                return null;
            }

            var view = detector._normalizer.Normalize(transformed).Normalized;
            if (view.Length > ObfuscationLimits.MaxViewLength)
            {
                _limitReached = true;
                return null;
            }

            _viewsLeft--;
            return view;
        }

        private void Report(string chain, int[] counts, int[] expectedCounts, string code, string description, double confidenceFactor)
        {
            for (var i = 0; i < counts.Length; i++)
            {
                var revealed = counts[i] - expectedCounts[i];
                if (revealed <= 0)
                {
                    continue;
                }

                var rule = detector._rules[i];
                _findings.Add(new ThreatFinding(
                    code,
                    ThreatCategory.Obfuscation,
                    rule.Severity > ThreatSeverity.High ? rule.Severity : ThreatSeverity.High,
                    Math.Round(rule.Confidence * confidenceFactor, 2),
                    description,
                    new FindingEvidence(DetectorId, $"OB-{chain}/{rule.Id}", revealed)));
            }
        }
    }
}
