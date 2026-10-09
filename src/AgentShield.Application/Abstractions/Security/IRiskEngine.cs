using AgentShield.Domain.Risk;
using AgentShield.Domain.Threats;

namespace AgentShield.Application.Abstractions.Security;

/// <summary>
/// Turns the findings of one analysis into a single, explainable risk assessment. Deterministic; knows nothing about
/// HTTP, decisions or LLMs.
/// </summary>
public interface IRiskEngine
{
    RiskAssessment Assess(IReadOnlyList<ThreatFinding> findings);
}
