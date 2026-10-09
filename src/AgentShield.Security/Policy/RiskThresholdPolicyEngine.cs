using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.Threats;

namespace AgentShield.Security.Policy;

/// <summary>
/// The initial policy: two risk thresholds, evaluated top-down. Changing the policy means changing these constants.
/// </summary>
/// <remarks>
/// <list type="table">
/// <item><term>Risk ≥ <see cref="BlockAt"/> (High, Critical)</term><description>Block (<c>Policy.BlockHighRisk</c>)</description></item>
/// <item><term>Risk ≥ <see cref="ReviewAt"/> (Medium)</term><description>Review (<c>Policy.ReviewMediumRisk</c>)</description></item>
/// <item><term>Low risk, with findings</term><description>Allow (<c>Policy.AllowLowRisk</c>)</description></item>
/// <item><term>No findings</term><description>Allow (<c>Policy.AllowNoThreats</c>)</description></item>
/// </list>
/// </remarks>
internal sealed class RiskThresholdPolicyEngine : IPolicyEngine, ISingletonService
{
    public const RiskLevel BlockAt = RiskLevel.High;
    public const RiskLevel ReviewAt = RiskLevel.Medium;

    public const string BlockHighRisk = "Policy.BlockHighRisk";
    public const string ReviewMediumRisk = "Policy.ReviewMediumRisk";
    public const string AllowLowRisk = "Policy.AllowLowRisk";
    public const string AllowNoThreats = "Policy.AllowNoThreats";

    public PolicyDecision Decide(RiskAssessment risk, IReadOnlyList<ThreatFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(risk);
        ArgumentNullException.ThrowIfNull(findings);

        if (risk.Level >= BlockAt)
        {
            return new PolicyDecision(
                SecurityDecision.Block,
                BlockHighRisk,
                $"Risk level {risk.Level} is at or above the block threshold ({BlockAt}).");
        }

        if (risk.Level >= ReviewAt)
        {
            return new PolicyDecision(
                SecurityDecision.Review,
                ReviewMediumRisk,
                $"Risk level {risk.Level} requires human review before the input proceeds.");
        }

        return findings.Count == 0
            ? new PolicyDecision(SecurityDecision.Allow, AllowNoThreats, "No threats were detected.")
            : new PolicyDecision(SecurityDecision.Allow, AllowLowRisk, "Only low-risk findings were detected.");
    }
}
