namespace AgentShield.Domain.Threats;

/// <summary>
/// One structured observation produced by a threat detector.
/// </summary>
/// <remarks>
/// <para>A finding never contains the analysed input, an excerpt of it or anything decoded from it:
/// <see cref="Description"/> is fixed text written by the detector author, and <see cref="Evidence"/> records which
/// detector and rule matched and how often. Findings can therefore be logged and returned to clients without leaking
/// user content.</para>
/// <para>A finding carries no location, so two findings with the same <see cref="Category"/> and <see cref="Code"/>
/// state the same fact about the same input. The finding aggregator fuses such duplicates into one finding and keeps
/// the evidence of the others in <see cref="CorroboratingEvidence"/>.</para>
/// </remarks>
public sealed record ThreatFinding
{
    private readonly IReadOnlyList<FindingEvidence> _corroboratingEvidence = [];

    public ThreatFinding(
        string code,
        ThreatCategory category,
        ThreatSeverity severity,
        double confidence,
        string description,
        FindingEvidence evidence)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        ArgumentException.ThrowIfNullOrWhiteSpace(description);
        ArgumentNullException.ThrowIfNull(evidence);

        if (!Enum.IsDefined(category))
        {
            throw new ArgumentOutOfRangeException(nameof(category), category, "Unknown threat category.");
        }

        if (!Enum.IsDefined(severity))
        {
            throw new ArgumentOutOfRangeException(nameof(severity), severity, "Unknown threat severity.");
        }

        // Also rejects NaN, for which every comparison is false.
        if (!(confidence is >= 0.0 and <= 1.0))
        {
            throw new ArgumentOutOfRangeException(nameof(confidence), confidence, "Confidence must be between 0 and 1.");
        }

        Code = code;
        Category = category;
        Severity = severity;
        Confidence = confidence;
        Description = description;
        Evidence = evidence;
    }

    /// <summary>Stable, machine-readable identifier of what was found (<c>Area.Reason</c>, e.g. <c>InstructionOverride.IgnorePrevious</c>).</summary>
    public string Code { get; }

    public ThreatCategory Category { get; }

    public ThreatSeverity Severity { get; }

    /// <summary>
    /// The detector author's estimate (0–1) that a match is a real attack rather than benign wording. A fixed property
    /// of the rule (heuristic), not a statistical measurement or calibrated probability.
    /// </summary>
    public double Confidence { get; }

    /// <summary>Client-safe explanation of the finding. Never contains analysed content.</summary>
    public string Description { get; }

    /// <summary>Evidence of the observation this finding was built from (after fusion: the most severe one).</summary>
    public FindingEvidence Evidence { get; }

    /// <summary>
    /// Evidence of duplicate findings (same category and code) fused into this one, in a deterministic order. Empty
    /// for a finding that only one detector rule reported.
    /// </summary>
    public IReadOnlyList<FindingEvidence> CorroboratingEvidence
    {
        get => _corroboratingEvidence;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            if (value.Any(evidence => evidence is null))
            {
                throw new ArgumentException("Corroborating evidence cannot contain null entries.", nameof(value));
            }

            _corroboratingEvidence = value;
        }
    }

    /// <summary><see cref="Evidence"/> followed by <see cref="CorroboratingEvidence"/>.</summary>
    public IEnumerable<FindingEvidence> AllEvidence => CorroboratingEvidence.Prepend(Evidence);
}

/// <summary>
/// Why a finding was raised, for audit and tuning. Internal to AgentShield: it identifies detectors and detection
/// rules, which would help an attacker probe for gaps, so it is logged but not returned to API clients.
/// </summary>
/// <param name="RuleId">Identifier of the rule that matched (e.g. <c>IO-001</c>, or <c>OB-B64/IO-001</c> for a rule
/// that matched only after decoding).</param>
/// <param name="MatchCount">How many times the rule matched (at least 1).</param>
public sealed record FindingEvidence(string RuleId, int MatchCount)
{
    /// <summary><see cref="Detector"/> of evidence created without naming its detector (e.g. by a test double).</summary>
    public const string UnattributedDetector = "Unattributed";

    /// <param name="detector">Stable identity of the detector that raised the finding (e.g. <c>InstructionOverride</c>).</param>
    /// <param name="ruleId">Identifier of the rule that matched.</param>
    /// <param name="matchCount">How many times the rule matched (at least 1).</param>
    public FindingEvidence(string detector, string ruleId, int matchCount)
        : this(ruleId, matchCount)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(detector);
        Detector = detector;
    }

    /// <summary>Stable identity of the detector that raised the finding. Audit data, like the rule ID.</summary>
    public string Detector { get; } = UnattributedDetector;

    public string RuleId { get; } = string.IsNullOrWhiteSpace(RuleId)
        ? throw new ArgumentException("A rule identifier is required.", nameof(RuleId))
        : RuleId;

    public int MatchCount { get; } = MatchCount >= 1
        ? MatchCount
        : throw new ArgumentOutOfRangeException(nameof(MatchCount), MatchCount, "Evidence requires at least one match.");
}
