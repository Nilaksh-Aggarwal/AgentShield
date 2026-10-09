using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.UnitTests.Domain;

public class AiAnalysisSummaryTests
{
    [Fact]
    public void Disabled_HasNoProviderModelFindingsOrDuration()
    {
        var disabled = AiAnalysisSummary.Disabled;

        Assert.Equal(AiAnalysisStatus.Disabled, disabled.Status);
        Assert.Null(disabled.Provider);
        Assert.Null(disabled.Model);
        Assert.Equal(0, disabled.FindingCount);
        Assert.Equal(TimeSpan.Zero, disabled.Duration);
    }

    [Fact]
    public void Constructor_Disabled_DropsAnyProviderAndModel()
    {
        var summary = new AiAnalysisSummary(AiAnalysisStatus.Disabled, "Provider", "model", 0, TimeSpan.Zero);

        Assert.Equal(AiAnalysisSummary.Disabled, summary);
    }

    [Theory]
    [InlineData(null, "model")]
    [InlineData(" ", "model")]
    [InlineData("Provider", null)]
    [InlineData("Provider", "")]
    public void Constructor_RanWithoutProviderOrModel_Throws(string? provider, string? model) =>
        Assert.ThrowsAny<ArgumentException>(() => new AiAnalysisSummary(AiAnalysisStatus.Completed, provider, model, 0, TimeSpan.Zero));

    [Theory]
    [InlineData(AiAnalysisStatus.TimedOut)]
    [InlineData(AiAnalysisStatus.Unavailable)]
    [InlineData(AiAnalysisStatus.InvalidResponse)]
    public void Constructor_FindingsFromAFailedAnalysis_Throws(AiAnalysisStatus status) =>
        Assert.Throws<ArgumentException>(() => new AiAnalysisSummary(status, "Provider", "model", 1, TimeSpan.Zero));

    [Fact]
    public void Constructor_UnknownStatusNegativeCountOrDuration_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new AiAnalysisSummary((AiAnalysisStatus)0, "Provider", "model", 0, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AiAnalysisSummary(AiAnalysisStatus.Completed, "Provider", "model", -1, TimeSpan.Zero));
        Assert.Throws<ArgumentOutOfRangeException>(() => new AiAnalysisSummary(AiAnalysisStatus.Completed, "Provider", "model", 0, TimeSpan.FromTicks(-1)));
    }

    [Fact]
    public void SecurityEvent_WithoutAiSummary_RecordsAiAsDisabled()
    {
        var securityEvent = NewEvent();

        Assert.Same(AiAnalysisSummary.Disabled, securityEvent.AiAnalysis);
    }

    [Fact]
    public void SecurityEvent_KeepsTheAiSummary_AndRejectsNull()
    {
        var summary = new AiAnalysisSummary(AiAnalysisStatus.Completed, "Provider", "model", 2, TimeSpan.FromMilliseconds(40));

        Assert.Same(summary, (NewEvent() with { AiAnalysis = summary }).AiAnalysis);
        Assert.Throws<ArgumentNullException>(() => NewEvent() with { AiAnalysis = null! });
    }

    private static SecurityEvent NewEvent() => new(
        SecurityEventId.New(),
        "req-1",
        DateTimeOffset.UnixEpoch,
        new PolicyDecision(SecurityDecision.Allow, "Policy.AllowNoThreats", "No threats were detected."),
        RiskAssessment.None,
        [],
        1,
        TimeSpan.Zero);
}
