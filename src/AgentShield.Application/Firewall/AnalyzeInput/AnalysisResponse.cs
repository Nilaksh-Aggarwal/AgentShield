using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.Threats;

namespace AgentShield.Application.Firewall.AnalyzeInput;

/// <summary>Result of a firewall analysis.</summary>
/// <param name="SecurityEventId">Identifier of the audit record of this analysis (distinct from the correlation ID).</param>
/// <param name="Decision">What the caller should do with the input.</param>
/// <param name="Reason">Why the policy decided as it did.</param>
/// <param name="Risk">Overall risk derived from the findings.</param>
/// <param name="Findings">What the detectors found, duplicates fused, most severe first. Empty for clean input.</param>
/// <param name="DurationMs">Time spent analysing, in milliseconds.</param>
public sealed record AnalysisResponse(
    Guid SecurityEventId,
    SecurityDecision Decision,
    string Reason,
    RiskResponse Risk,
    IReadOnlyList<FindingResponse> Findings,
    double DurationMs);

/// <param name="Level">Low (0–29), Medium (30–69), High (70–89) or Critical (90–100).</param>
/// <param name="Score">Prototype risk score from 0 to 100; not a calibrated probability.</param>
public sealed record RiskResponse(RiskLevel Level, int Score);

/// <summary>
/// A finding as shown to clients. Deliberately omits the detector, matched rules and match counts (audit data) and never
/// contains analysed or decoded content.
/// </summary>
/// <param name="Code">Stable identifier of what was found (<c>Area.Reason</c>).</param>
/// <param name="Category">Kind of attack.</param>
/// <param name="Severity">Harm indicated by this finding alone.</param>
/// <param name="Confidence">Detector author's heuristic estimate (0–1) that a match is a real attack; not calibrated.</param>
/// <param name="Description">Explanation of the finding.</param>
public sealed record FindingResponse(
    string Code,
    ThreatCategory Category,
    ThreatSeverity Severity,
    double Confidence,
    string Description);
