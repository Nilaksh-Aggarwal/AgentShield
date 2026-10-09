using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Domain.Threats;

namespace AgentShield.Security.Aggregation;

/// <summary>
/// Fuses duplicate findings and puts the result in a fixed order. Pure and deterministic: the output depends only on
/// the set of findings, never on the order detectors ran in.
/// </summary>
/// <remarks>
/// <para><b>Deduplication key:</b> (<see cref="ThreatFinding.Category"/>, <see cref="ThreatFinding.Code"/>). Findings
/// carry no location or excerpt (so they can never leak input), which means two findings with the same category and
/// code say the same thing about the same input; the code already identifies the rule semantics. The category is part
/// of the key so that two detectors that happen to reuse a code for different categories are not merged.</para>
/// <para><b>Fusion of a duplicate group:</b></para>
/// <list type="bullet">
/// <item>Severity: the highest in the group.</item>
/// <item>Confidence: the highest in the group. Confidences are not combined (no noisy-OR or averaging): fusion never
/// makes a finding more confident than its most confident source. Confidence weighting belongs to the risk engine.</item>
/// <item>Description and primary <see cref="ThreatFinding.Evidence"/>: from the representative, the member with the
/// highest severity, then highest confidence, then smallest (detector, rule ID) ordinal, then highest match count, then
/// description (ordinal), so the choice never depends on input order.</item>
/// <item><see cref="ThreatFinding.CorroboratingEvidence"/>: the distinct evidence of every other member (and any
/// evidence they already carried), ordered by detector, rule ID and match count. Nothing is lost.</item>
/// </list>
/// <para><b>Order:</b> severity (Critical first), then category (declaration order of <see cref="ThreatCategory"/>),
/// then code (ordinal). After deduplication no two findings share category and code, so the order is total.</para>
/// </remarks>
internal sealed class FindingAggregator : IFindingAggregator, ISingletonService
{
    public IReadOnlyList<ThreatFinding> Aggregate(IReadOnlyList<ThreatFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        if (findings.Count == 0)
        {
            return [];
        }

        var fused = findings
            .GroupBy(finding => (finding.Category, finding.Code))
            .Select(group => Fuse([.. group]))
            .ToList();

        fused.Sort(CompareForOutput);
        return fused.AsReadOnly();
    }

    private static ThreatFinding Fuse(ThreatFinding[] group)
    {
        if (group.Length == 1 && group[0].CorroboratingEvidence.Count == 0)
        {
            return group[0];
        }

        Array.Sort(group, CompareForRepresentative);
        var representative = group[0];

        var corroborating = group
            .SelectMany(finding => finding.AllEvidence)
            .Distinct()
            .Where(evidence => evidence != representative.Evidence)
            .Order(EvidenceComparer.Instance)
            .ToArray();

        return new ThreatFinding(
            representative.Code,
            representative.Category,
            representative.Severity,
            group.Max(finding => finding.Confidence),
            representative.Description,
            representative.Evidence)
        {
            CorroboratingEvidence = corroborating,
        };
    }

    private static int CompareForOutput(ThreatFinding left, ThreatFinding right)
    {
        var bySeverity = right.Severity.CompareTo(left.Severity);
        if (bySeverity != 0)
        {
            return bySeverity;
        }

        var byCategory = left.Category.CompareTo(right.Category);
        return byCategory != 0 ? byCategory : string.CompareOrdinal(left.Code, right.Code);
    }

    private static int CompareForRepresentative(ThreatFinding left, ThreatFinding right)
    {
        var bySeverity = right.Severity.CompareTo(left.Severity);
        if (bySeverity != 0)
        {
            return bySeverity;
        }

        var byConfidence = right.Confidence.CompareTo(left.Confidence);
        if (byConfidence != 0)
        {
            return byConfidence;
        }

        var byEvidence = EvidenceComparer.Instance.Compare(left.Evidence, right.Evidence);
        return byEvidence != 0 ? byEvidence : string.CompareOrdinal(left.Description, right.Description);
    }

    private sealed class EvidenceComparer : IComparer<FindingEvidence>
    {
        public static readonly EvidenceComparer Instance = new();

        public int Compare(FindingEvidence? x, FindingEvidence? y)
        {
            if (ReferenceEquals(x, y))
            {
                return 0;
            }

            if (x is null || y is null)
            {
                return x is null ? -1 : 1;
            }

            var byDetector = string.CompareOrdinal(x.Detector, y.Detector);
            if (byDetector != 0)
            {
                return byDetector;
            }

            var byRule = string.CompareOrdinal(x.RuleId, y.RuleId);

            // Higher match count first, so the representative is the strongest observation of that rule.
            return byRule != 0 ? byRule : y.MatchCount.CompareTo(x.MatchCount);
        }
    }
}
