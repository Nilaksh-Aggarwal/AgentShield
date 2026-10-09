using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Security.AiAnalysis;

namespace AgentShield.SecurityTests.AiAnalysis;

/// <summary>
/// The failure table: since Milestone 6 step 2 every failure of an expected AI analysis holds the input for review;
/// nothing falls back to the deterministic decision alone.
/// </summary>
public class AiFailurePolicyTests
{
    [Theory]
    [InlineData(AiAnalysisStatus.Unavailable)]
    [InlineData(AiAnalysisStatus.RateLimited)]
    [InlineData(AiAnalysisStatus.NetworkFailure)]
    [InlineData(AiAnalysisStatus.TimedOut)]
    [InlineData(AiAnalysisStatus.CircuitOpen)]
    public void For_ProviderAvailabilityFailureOrOpenCircuit_HoldsForReview_NotDeterministicOnly(AiAnalysisStatus status) =>
        Assert.Equal(AiFailureHandling.Review, AiFailurePolicy.For(status));

    [Theory]
    [InlineData(AiAnalysisStatus.ContentWithheld)]
    [InlineData(AiAnalysisStatus.MalformedResponse)]
    [InlineData(AiAnalysisStatus.InvalidResponse)]
    [InlineData(AiAnalysisStatus.Refused)]
    [InlineData(AiAnalysisStatus.UnclassifiedFailure)]
    [InlineData(AiAnalysisStatus.CapacityExceeded)]
    public void For_FailureTheInputOrTheCallerCouldCause_HoldsForReview(AiAnalysisStatus status) =>
        Assert.Equal(AiFailureHandling.Review, AiFailurePolicy.For(status));

    [Fact]
    public void For_EveryFailureStatus_HasAnExplicitHandling()
    {
        // A status added later without a row in the table must fail here, not default silently.
        var failures = Enum.GetValues<AiAnalysisStatus>()
            .Where(status => status is not (AiAnalysisStatus.Disabled or AiAnalysisStatus.Completed or AiAnalysisStatus.NotNeeded));

        Assert.All(failures, status => Assert.Equal(AiFailureHandling.Review, AiFailurePolicy.For(status)));
    }

    [Theory]
    [InlineData(AiAnalysisStatus.Disabled)]
    [InlineData(AiAnalysisStatus.Completed)]
    [InlineData(AiAnalysisStatus.NotNeeded)]
    [InlineData((AiAnalysisStatus)99)]
    public void For_NotAFailure_Throws(AiAnalysisStatus status) =>
        Assert.Throws<ArgumentOutOfRangeException>(() => AiFailurePolicy.For(status));

    [Theory]
    [InlineData(AiAnalysisStatus.RateLimited, true)]
    [InlineData(AiAnalysisStatus.Unavailable, true)]
    [InlineData(AiAnalysisStatus.NetworkFailure, true)]
    [InlineData(AiAnalysisStatus.TimedOut, true)]
    [InlineData(AiAnalysisStatus.UnclassifiedFailure, false)]
    [InlineData(AiAnalysisStatus.MalformedResponse, false)]
    [InlineData(AiAnalysisStatus.InvalidResponse, false)]
    [InlineData(AiAnalysisStatus.Refused, false)]
    [InlineData(AiAnalysisStatus.Completed, false)]
    [InlineData(AiAnalysisStatus.ContentWithheld, false)]
    [InlineData(AiAnalysisStatus.CapacityExceeded, false)]
    [InlineData(AiAnalysisStatus.CircuitOpen, false)]
    public void Availability_OnlyProviderSideUnavailabilityCountsForTheCircuit(AiAnalysisStatus status, bool availabilityFailure)
    {
        Assert.Equal(availabilityFailure, AiProviderAvailability.IsAvailabilityFailure(status));

        // "The provider answered" and "the provider was unavailable" never overlap; statuses without a call are neither.
        Assert.False(AiProviderAvailability.IsAvailabilityFailure(status) && AiProviderAvailability.ProviderResponded(status));
    }

    [Theory]
    [InlineData(AiAnalysisStatus.Completed)]
    [InlineData(AiAnalysisStatus.MalformedResponse)]
    [InlineData(AiAnalysisStatus.InvalidResponse)]
    [InlineData(AiAnalysisStatus.Refused)]
    [InlineData(AiAnalysisStatus.UnclassifiedFailure)]
    public void Availability_AnyAnswerFromTheProvider_ProvesItIsReachable(AiAnalysisStatus status) =>
        Assert.True(AiProviderAvailability.ProviderResponded(status));
}
