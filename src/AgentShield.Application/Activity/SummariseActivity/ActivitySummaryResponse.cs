namespace AgentShield.Application.Activity.SummariseActivity;

/// <summary>
/// Counts over the security activity history as it is held right now: every number comes from the same snapshot, so they
/// add up. Counts only — no event, ID, name or content.
/// </summary>
/// <remarks>
/// The history is held in this API process's memory: the most recent events only (bounded), emptied on restart, every
/// client's activity together. These are counts of what it holds, not a measure over any period, and not the audit trail.
/// </remarks>
/// <param name="TotalCount">Events the history holds.</param>
/// <param name="OldestOccurredAt">When the oldest of them was decided; <c>null</c> when the history is empty.</param>
/// <param name="NewestOccurredAt">When the newest of them was decided; <c>null</c> when the history is empty.</param>
/// <param name="Decisions">How many were allowed, held for review and blocked.</param>
/// <param name="Kinds">How many were input analyses, agent action authorizations and tool calls through the gateway.</param>
/// <param name="ToolsExecuted">Tool calls whose tool ran and returned a result (outcome <c>Executed</c>).</param>
public sealed record ActivitySummaryResponse(
    int TotalCount,
    DateTimeOffset? OldestOccurredAt,
    DateTimeOffset? NewestOccurredAt,
    ActivityDecisionCounts Decisions,
    ActivityKindCounts Kinds,
    int ToolsExecuted);

/// <param name="Allow">Events decided Allow.</param>
/// <param name="Review">Events decided Review.</param>
/// <param name="Block">Events decided Block.</param>
public sealed record ActivityDecisionCounts(int Allow, int Review, int Block);

/// <param name="InputAnalysis">Inputs analysed by the firewall.</param>
/// <param name="AgentActionAuthorization">Agent actions decided by the authorization boundary (nothing executed).</param>
/// <param name="ToolExecution">Tool calls through the tool gateway (executed or not).</param>
public sealed record ActivityKindCounts(int InputAnalysis, int AgentActionAuthorization, int ToolExecution);
