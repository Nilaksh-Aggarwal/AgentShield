using System.Text.RegularExpressions;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Domain.Threats;

namespace AgentShield.Security.Detection;

/// <summary>A deterministic detection rule: a pattern and what a match means.</summary>
/// <param name="Id">Rule identifier recorded as evidence (audit only; not returned to clients).</param>
/// <param name="Code">Finding code reported when the rule matches.</param>
/// <param name="Severity">Severity of a match.</param>
/// <param name="Confidence">Author's heuristic estimate (0–1) that a match is a real attack.</param>
/// <param name="Description">Client-safe explanation of a match.</param>
/// <param name="Pattern">
/// Pattern matched against the normalised input. Patterns must use <see cref="RegexOptions.NonBacktracking"/> (linear
/// time, no catastrophic backtracking on hostile input) and a match timeout.
/// </param>
internal sealed record PatternRule(
    string Id,
    string Code,
    ThreatSeverity Severity,
    double Confidence,
    string Description,
    Regex Pattern);

/// <summary>
/// Shared mechanics for detectors built from <see cref="PatternRule"/>s: one finding per matching rule, carrying the
/// detector identity, rule ID and match count as evidence. Subclasses only declare their category and rules.
/// </summary>
internal abstract class PatternThreatDetector : IThreatDetector, IPatternRuleSource
{
    private readonly ThreatCategory _category;
    private readonly IReadOnlyList<PatternRule> _rules;

    protected PatternThreatDetector(ThreatCategory category, IReadOnlyList<PatternRule> rules)
    {
        ArgumentNullException.ThrowIfNull(rules);

        _category = category;
        _rules = rules;
        DetectorId = category.ToString();
    }

    /// <summary>Stable detector identity recorded in evidence: the name of the category the detector owns.</summary>
    public string DetectorId { get; }

    /// <summary>The rules of this detector, for tests, documentation and re-use on decoded content.</summary>
    public IReadOnlyList<PatternRule> Rules => _rules;

    public IReadOnlyList<ThreatFinding> Detect(NormalizedInput input)
    {
        ArgumentNullException.ThrowIfNull(input);

        if (input.Normalized.Length == 0)
        {
            return [];
        }

        List<ThreatFinding>? findings = null;
        foreach (var rule in _rules)
        {
            // A RegexMatchTimeoutException is deliberately not caught: the analysis fails (fail closed) instead of
            // deciding as if the rule had not matched. NonBacktracking patterns make this practically unreachable.
            var matches = rule.Pattern.Count(input.Normalized);
            if (matches > 0)
            {
                (findings ??= []).Add(new ThreatFinding(
                    rule.Code,
                    _category,
                    rule.Severity,
                    rule.Confidence,
                    rule.Description,
                    new FindingEvidence(DetectorId, rule.Id, matches)));
            }
        }

        return findings is null ? [] : findings;
    }
}
