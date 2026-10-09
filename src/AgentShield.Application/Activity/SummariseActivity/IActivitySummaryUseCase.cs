using AgentShield.Application.Common.Results;

namespace AgentShield.Application.Activity.SummariseActivity;

/// <summary>Counts the security activity history by decision and kind, from one snapshot. Read-only.</summary>
public interface IActivitySummaryUseCase
{
    Task<Result<ActivitySummaryResponse>> ExecuteAsync(CancellationToken cancellationToken);
}
