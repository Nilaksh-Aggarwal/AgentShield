using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Domain.Risk;
using AgentShield.Domain.Threats;

namespace AgentShield.Security.Risk;

/// <summary>
/// Prototype risk model: the most severe finding sets the level, and each further finding adds a little weight within
/// that level. Deterministic and explainable in one sentence; not statistically calibrated.
/// </summary>
/// <remarks>
/// <list type="number">
/// <item>No findings → score 0 (<see cref="RiskLevel.Low"/>).</item>
/// <item>Otherwise the base score of the highest severity: Low 10, Medium 40, High 70, Critical 90.</item>
/// <item>Plus <see cref="AdditionalFindingPoints"/> for every other finding (corroboration).</item>
/// <item>Capped at the top of the band of the highest severity (29 / 69 / 89 / 100), so the risk level always equals
/// the highest finding severity: many weak signals never add up to a stronger level.</item>
/// </list>
/// Confidence is reported with each finding but does not change the score yet.
/// </remarks>
internal sealed class SeverityRiskEngine : IRiskEngine, ISingletonService
{
    public const int AdditionalFindingPoints = 5;

    public RiskAssessment Assess(IReadOnlyList<ThreatFinding> findings)
    {
        ArgumentNullException.ThrowIfNull(findings);

        if (findings.Count == 0)
        {
            return RiskAssessment.None;
        }

        var highest = findings.Max(finding => finding.Severity);
        var level = LevelFor(highest);

        var score = BaseScoreFor(highest) + (AdditionalFindingPoints * (findings.Count - 1));

        return new RiskAssessment(Math.Min(score, RiskAssessment.MaxScoreFor(level)));
    }

    public static int BaseScoreFor(ThreatSeverity severity) => severity switch
    {
        ThreatSeverity.Low => 10,
        ThreatSeverity.Medium => 40,
        ThreatSeverity.High => 70,
        ThreatSeverity.Critical => 90,
        _ => throw new ArgumentOutOfRangeException(nameof(severity), severity, "Unknown threat severity."),
    };

    private static RiskLevel LevelFor(ThreatSeverity severity) => severity switch
    {
        ThreatSeverity.Low => RiskLevel.Low,
        ThreatSeverity.Medium => RiskLevel.Medium,
        ThreatSeverity.High => RiskLevel.High,
        ThreatSeverity.Critical => RiskLevel.Critical,
        _ => throw new ArgumentOutOfRangeException(nameof(severity), severity, "Unknown threat severity."),
    };
}
