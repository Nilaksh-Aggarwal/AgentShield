using System.Reflection;
using System.Text.Json;
using AgentShield.Application.Activity;
using AgentShield.Domain.Policy;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Domain.Threats;
using static AgentShield.UnitTests.Application.Activity.ActivityTestEvents;

namespace AgentShield.UnitTests.Application.Activity;

public class SecurityActivityRecordTests
{
    [Theory]
    [InlineData(SecurityDecision.Allow, 0)]
    [InlineData(SecurityDecision.Review, 45)]
    [InlineData(SecurityDecision.Block, 94)]
    public void FromSecurityEvent_KeepsTheFinalDecisionRiskAndIdentifiers(SecurityDecision decision, int score)
    {
        var securityEvent = Event(decision, score, "corr-kept-1", Start.AddMinutes(3));

        var record = SecurityActivityRecord.FromSecurityEvent(securityEvent);

        Assert.Equal(securityEvent.Id.Value, record.SecurityEventId);
        Assert.Equal("corr-kept-1", record.CorrelationId);
        Assert.Equal(Start.AddMinutes(3), record.OccurredAt);
        Assert.Equal(SecurityActivityKind.InputAnalysis, record.Kind);
        Assert.Equal(decision, record.Decision);
        Assert.Equal(new ActivityRisk(securityEvent.Risk.Level, score), record.Risk);
        Assert.Null(record.AgentAction);
    }

    [Theory]
    [InlineData(SecurityDecision.Allow, 94)]
    [InlineData(SecurityDecision.Block, 0)]
    [InlineData(SecurityDecision.Review, 100)]
    public void FromSecurityEvent_CopiesTheDecision_NeverRecomputesItFromTheRisk(SecurityDecision decision, int score)
    {
        // Deliberately inconsistent with the policy thresholds: the record repeats what was decided, so the history can
        // never show (or become) a different decision than the one returned to the caller.
        var record = SecurityActivityRecord.FromSecurityEvent(Event(decision, score));

        Assert.Equal((decision, score), (record.Decision, record.Risk.Score));
    }

    [Fact]
    public void FromSecurityEvent_KeepsEachFindingsCodeCategoryAndSeverity_InTheAnalysisOrder()
    {
        var securityEvent = Event(SecurityDecision.Block, 95, findings:
        [
            Finding("RoleManipulation.ForgedRoleDelimiter", ThreatCategory.RoleManipulation, ThreatSeverity.Critical),
            Finding("InstructionOverride.IgnorePrevious", ThreatCategory.InstructionOverride, ThreatSeverity.High),
            Finding("Obfuscation.EncodedThreat", ThreatCategory.Obfuscation, ThreatSeverity.High),
        ]);

        var record = SecurityActivityRecord.FromSecurityEvent(securityEvent);

        Assert.Equal(
            [
                new ActivityFinding("RoleManipulation.ForgedRoleDelimiter", ThreatCategory.RoleManipulation, ThreatSeverity.Critical),
                new ActivityFinding("InstructionOverride.IgnorePrevious", ThreatCategory.InstructionOverride, ThreatSeverity.High),
                new ActivityFinding("Obfuscation.EncodedThreat", ThreatCategory.Obfuscation, ThreatSeverity.High),
            ],
            record.Findings);
    }

    public static TheoryData<AiAnalysisStatus, ActivityAiStatus> AiStatuses() => new()
    {
        { AiAnalysisStatus.Disabled, ActivityAiStatus.Disabled },
        { AiAnalysisStatus.Completed, ActivityAiStatus.Completed },
        { AiAnalysisStatus.NotNeeded, ActivityAiStatus.NotNeeded },
        { AiAnalysisStatus.ContentWithheld, ActivityAiStatus.Incomplete },
        { AiAnalysisStatus.TimedOut, ActivityAiStatus.Incomplete },
        { AiAnalysisStatus.Unavailable, ActivityAiStatus.Incomplete },
        { AiAnalysisStatus.RateLimited, ActivityAiStatus.Incomplete },
        { AiAnalysisStatus.NetworkFailure, ActivityAiStatus.Incomplete },
        { AiAnalysisStatus.MalformedResponse, ActivityAiStatus.Incomplete },
        { AiAnalysisStatus.InvalidResponse, ActivityAiStatus.Incomplete },
        { AiAnalysisStatus.Refused, ActivityAiStatus.Incomplete },
        { AiAnalysisStatus.UnclassifiedFailure, ActivityAiStatus.Incomplete },
        { AiAnalysisStatus.CapacityExceeded, ActivityAiStatus.Incomplete },
        { AiAnalysisStatus.CircuitOpen, ActivityAiStatus.Incomplete },
    };

    [Theory]
    [MemberData(nameof(AiStatuses))]
    public void FromSecurityEvent_ReducesTheAiStatus_SoNoFailureReasonIsKept(AiAnalysisStatus status, ActivityAiStatus expected)
    {
        var ai = new AiAnalysisSummary(status, "Gemini", "gemini-test-model", 0, TimeSpan.FromSeconds(3));

        var record = SecurityActivityRecord.FromSecurityEvent(Event(SecurityDecision.Review, 40, ai: ai));

        Assert.Equal(expected, record.AiAnalysis);
    }

    [Fact]
    public void AiStatuses_CoverEveryAuditStatus()
    {
        var covered = AiStatuses().Select(row => (AiAnalysisStatus)row[0]);

        Assert.Equal(Enum.GetValues<AiAnalysisStatus>().Order(), covered.Order());
    }

    [Fact]
    public void Record_HoldsMetadataOnly_AndCanOnlyBeBuiltFromASecurityEvent()
    {
        // Privacy by construction: adding a field (input, length, timing, rule IDs, provider, a description) fails here and
        // needs a deliberate decision. The only text is the correlation ID and fixed finding codes.
        Assert.Equal(
            ["AgentAction", "AiAnalysis", "CorrelationId", "Decision", "Findings", "Kind", "OccurredAt", "Risk", "SecurityEventId", "ToolExecution"],
            PublicProperties<SecurityActivityRecord>());
        Assert.Equal(["Level", "Score"], PublicProperties<ActivityRisk>());
        Assert.Equal(["Action", "AgentId", "Capability", "Reason", "Tool"], PublicProperties<ActivityAgentAction>());
        Assert.Equal(["Category", "Code", "Severity"], PublicProperties<ActivityFinding>());
        Assert.Equal(["Executed", "ExecutionId", "Outcome"], PublicProperties<ActivityToolExecution>());
        Assert.Empty(typeof(SecurityActivityRecord).GetConstructors());
    }

    [Fact]
    public void FromSecurityEvent_KeepsNoRuleIdDetectorDescriptionProviderModelOrFailureReason()
    {
        const string Marker = "zq7activity";
        var finding = new ThreatFinding(
            "InstructionOverride.IgnorePrevious",
            ThreatCategory.InstructionOverride,
            ThreatSeverity.High,
            0.9,
            $"Description {Marker}",
            new FindingEvidence($"Detector{Marker}", $"OB-B64/{Marker}", 3));
        var ai = new AiAnalysisSummary(AiAnalysisStatus.TimedOut, $"Provider{Marker}", $"model-{Marker}", 0, TimeSpan.FromMilliseconds(3001));

        var record = SecurityActivityRecord.FromSecurityEvent(Event(SecurityDecision.Review, 60, ai: ai, findings: [finding]));
        var serialised = JsonSerializer.Serialize(record);

        Assert.DoesNotContain(Marker, serialised, StringComparison.Ordinal);
        Assert.DoesNotContain("TimedOut", serialised, StringComparison.Ordinal);
        Assert.DoesNotContain("OB-B64", serialised, StringComparison.Ordinal);
    }

    [Fact]
    public void FromSecurityEvent_Null_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => SecurityActivityRecord.FromSecurityEvent(null!));
    }

    private static string[] PublicProperties<T>() =>
        [.. typeof(T).GetProperties(BindingFlags.Public | BindingFlags.Instance).Select(property => property.Name).Order(StringComparer.Ordinal)];
}
