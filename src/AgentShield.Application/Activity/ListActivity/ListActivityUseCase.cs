using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Common.Results;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;

namespace AgentShield.Application.Activity.ListActivity;

/// <summary>
/// Pages through the activity history. Maps stored records to the response field by field, so a field added to the record
/// later is not returned until it is added here deliberately.
/// </summary>
internal sealed class ListActivityUseCase(ISecurityActivityStore store) : IListActivityUseCase, IScopedService
{
    public async Task<Result<ActivityPageResponse>> ExecuteAsync(ListActivityRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var page = request.Page ?? 1;
        var pageSize = request.PageSize ?? ListActivityRequest.DefaultPageSize;
        var decisions = (request.Decision ?? []).Select(name => Parse(ListActivityRequest.DecisionNames, name)).ToHashSet();
        RiskLevel? minRiskLevel = request.MinRiskLevel is { } level ? Parse(ListActivityRequest.RiskLevelNames, level) : null;

        var slice = await store.QueryAsync(new SecurityActivityQuery(decisions, minRiskLevel, (page - 1) * pageSize, pageSize), cancellationToken);

        return new ActivityPageResponse(
            [.. slice.Records.Select(record => new ActivityItemResponse(
                record.SecurityEventId,
                record.CorrelationId,
                record.OccurredAt,
                record.Kind,
                record.Decision,
                new ActivityRiskResponse(record.Risk.Level, record.Risk.Score),
                [.. record.Findings.Select(finding => new ActivityFindingResponse(finding.Code, finding.Category, finding.Severity))],
                record.AiAnalysis,
                record.AgentAction is { } action
                    ? new ActivityAgentActionResponse(action.AgentId, action.Tool, action.Action, action.Capability, action.Reason)
                    : null,
                record.ToolExecution is { } execution
                    ? new ActivityToolExecutionResponse(execution.Outcome, execution.Executed, execution.ExecutionId)
                    : null))],
            page,
            pageSize,
            slice.TotalCount,
            (slice.TotalCount + pageSize - 1) / pageSize);
    }

    private static TEnum Parse<TEnum>(IReadOnlyDictionary<string, TEnum> names, string? name)
        where TEnum : struct, Enum =>
        name is not null && names.TryGetValue(name, out var value)
            ? value
            : throw new ArgumentException("The request must be validated before the activity history is read.", nameof(name));
}
