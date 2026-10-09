using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Common.Results;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;

namespace AgentShield.Application.Activity.SummariseActivity;

/// <summary>
/// Counts what the activity history holds. One bounded read of the whole history (the store holds at most its capacity),
/// so every count describes the same snapshot; the counts copy each record's decision, kind and outcome, never recompute
/// them.
/// </summary>
internal sealed class ActivitySummaryUseCase(ISecurityActivityStore store) : IActivitySummaryUseCase, IScopedService
{
    public async Task<Result<ActivitySummaryResponse>> ExecuteAsync(CancellationToken cancellationToken)
    {
        var slice = await store.QueryAsync(new SecurityActivityQuery(new HashSet<SecurityDecision>(), MinRiskLevel: null, Skip: 0, Take: int.MaxValue), cancellationToken);
        var records = slice.Records;

        return new ActivitySummaryResponse(
            records.Count,
            records.Count == 0 ? null : records.Min(record => record.OccurredAt),
            records.Count == 0 ? null : records.Max(record => record.OccurredAt),
            new ActivityDecisionCounts(
                records.Count(record => record.Decision == SecurityDecision.Allow),
                records.Count(record => record.Decision == SecurityDecision.Review),
                records.Count(record => record.Decision == SecurityDecision.Block)),
            new ActivityKindCounts(
                records.Count(record => record.Kind == SecurityActivityKind.InputAnalysis),
                records.Count(record => record.Kind == SecurityActivityKind.AgentActionAuthorization),
                records.Count(record => record.Kind == SecurityActivityKind.ToolExecution)),
            records.Count(record => record.ToolExecution is { Outcome: ToolExecutionOutcome.Executed }));
    }
}
