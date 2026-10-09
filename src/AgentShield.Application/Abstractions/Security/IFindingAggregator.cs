using AgentShield.Domain.Threats;

namespace AgentShield.Application.Abstractions.Security;

/// <summary>
/// Fuses the raw findings of every detector into the list that risk, policy, the security event and the response
/// use: duplicates merged, order deterministic. Deterministic; decides nothing.
/// </summary>
/// <remarks>
/// Contract for implementations:
/// <list type="bullet">
/// <item>The result must not depend on detector execution order: any permutation of the same findings yields the same
/// list.</item>
/// <item>Findings that state the same fact (same category and code) become one finding that keeps the highest
/// severity, the highest confidence and the evidence of every duplicate. Distinct findings are all kept.</item>
/// <item>No finding is invented and none is dropped without its evidence being kept.</item>
/// </list>
/// </remarks>
public interface IFindingAggregator
{
    IReadOnlyList<ThreatFinding> Aggregate(IReadOnlyList<ThreatFinding> findings);
}
