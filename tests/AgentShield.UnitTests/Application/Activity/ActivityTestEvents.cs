using AgentShield.Application.Activity;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Domain.Threats;

namespace AgentShield.UnitTests.Application.Activity;

/// <summary>Security events and activity records for activity tests.</summary>
internal static class ActivityTestEvents
{
    public static readonly DateTimeOffset Start = new(2026, 10, 1, 10, 0, 0, TimeSpan.Zero);

    public static SecurityEvent Event(
        SecurityDecision decision,
        int score,
        string correlationId = "corr-activity",
        DateTimeOffset? occurredAt = null,
        AiAnalysisSummary? ai = null,
        params ThreatFinding[] findings) =>
        new(
            SecurityEventId.New(),
            correlationId,
            occurredAt ?? Start,
            new PolicyDecision(decision, $"Policy.Test{decision}", $"{decision} for test."),
            new RiskAssessment(score),
            findings,
            42,
            TimeSpan.FromMilliseconds(5))
        {
            AiAnalysis = ai ?? AiAnalysisSummary.Disabled,
        };

    public static SecurityActivityRecord Record(SecurityDecision decision, int score, string correlationId = "corr-activity") =>
        SecurityActivityRecord.FromSecurityEvent(Event(decision, score, correlationId));

    public static ThreatFinding Finding(string code, ThreatCategory category, ThreatSeverity severity, string ruleId = "T-001") =>
        new(code, category, severity, 0.9, "Fixed description for test.", new FindingEvidence("TestDetector", ruleId, 2));
}
