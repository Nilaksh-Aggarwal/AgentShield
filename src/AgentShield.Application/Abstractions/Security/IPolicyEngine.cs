using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.Threats;

namespace AgentShield.Application.Abstractions.Security;

/// <summary>
/// The final, deterministic security authority: maps risk and findings to a decision. Detectors and (future) AI
/// analysis only contribute findings; they never decide.
/// </summary>
public interface IPolicyEngine
{
    PolicyDecision Decide(RiskAssessment risk, IReadOnlyList<ThreatFinding> findings);
}
