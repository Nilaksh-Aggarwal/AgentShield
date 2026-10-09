using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.Threats;

namespace AgentShield.Application.Activity.ListActivity;

/// <summary>One page of the security activity history, newest first.</summary>
/// <param name="Items">The records on this page; empty when nothing matches or the page is after the last one.</param>
/// <param name="Page">The page returned (1-based).</param>
/// <param name="PageSize">Records per page.</param>
/// <param name="TotalCount">Records matching the filters, across all pages.</param>
/// <param name="TotalPages">Pages of matching records; 0 when nothing matches.</param>
public sealed record ActivityPageResponse(
    IReadOnlyList<ActivityItemResponse> Items,
    int Page,
    int PageSize,
    int TotalCount,
    int TotalPages);

/// <summary>
/// A security event as the activity history shows it: security metadata only. Never the input, decoded content, rule IDs,
/// detector identities, provider output, the reason an AI analysis failed, or tool arguments.
/// </summary>
/// <remarks>Every item has every field; the fields of the other kind are <c>null</c> (or an empty list of findings).</remarks>
/// <param name="SecurityEventId">Identity of the security event (the decision response and the audit log carry it too).</param>
/// <param name="CorrelationId">The request that raised the event.</param>
/// <param name="OccurredAt">When the decision was made.</param>
/// <param name="Kind">What the event is about: an input analysis, an agent action authorization or a tool execution.</param>
/// <param name="Decision">The decision returned to the caller.</param>
/// <param name="Risk">The risk the decision was based on.</param>
/// <param name="Findings">What was found, duplicates fused, most severe first. Empty for a clean input and for an agent action.</param>
/// <param name="AiAnalysis">What AI-assisted analysis contributed to an input analysis, without a failure reason;
/// <c>null</c> for an agent action.</param>
/// <param name="AgentAction">The agent action and the authorization boundary's reason; <c>null</c> for an input analysis.</param>
/// <param name="ToolExecution">How the tool gateway handled a tool execution request; <c>null</c> for the other kinds.</param>
public sealed record ActivityItemResponse(
    Guid SecurityEventId,
    string CorrelationId,
    DateTimeOffset OccurredAt,
    SecurityActivityKind Kind,
    SecurityDecision Decision,
    ActivityRiskResponse Risk,
    IReadOnlyList<ActivityFindingResponse> Findings,
    ActivityAiStatus? AiAnalysis,
    ActivityAgentActionResponse? AgentAction,
    ActivityToolExecutionResponse? ToolExecution);

/// <param name="Level">Low, Medium, High or Critical.</param>
/// <param name="Score">The input's prototype risk score from 0 to 100; <c>null</c> for an agent action, whose risk is a
/// classification of the action without a score.</param>
public sealed record ActivityRiskResponse(RiskLevel Level, int? Score);

/// <param name="Code">Stable identifier of what was found (<c>Area.Reason</c>).</param>
/// <param name="Category">Kind of attack.</param>
/// <param name="Severity">Harm indicated by this finding alone.</param>
public sealed record ActivityFindingResponse(string Code, ThreatCategory Category, ThreatSeverity Severity);

/// <summary>
/// An agent action as the activity history shows it. Names come only from AgentShield's own configuration: one the caller
/// made up is <c>null</c>, never echoed.
/// </summary>
/// <param name="AgentId">The configured agent, or <c>null</c> when the request named an unknown one.</param>
/// <param name="Tool">The catalogued tool, or <c>null</c>.</param>
/// <param name="Action">The catalogued action, or <c>null</c>.</param>
/// <param name="Capability">The capability the agent claimed, when the catalogue knows it; otherwise <c>null</c>.</param>
/// <param name="Reason">Coarse reason code for the decision.</param>
public sealed record ActivityAgentActionResponse(string? AgentId, string? Tool, string? Action, string? Capability, AgentActionReason Reason);

/// <summary>
/// How the tool gateway handled one execution request, as the activity history shows it. Never the arguments, the tool's
/// result or why the arguments or a grant were rejected.
/// </summary>
/// <param name="Outcome">How the request ended (which stage stopped it, if any).</param>
/// <param name="Executed">Whether the tool was invoked.</param>
/// <param name="ExecutionId">The execution grant's ID when one was issued; <c>null</c> otherwise. An audit identifier, not a credential.</param>
public sealed record ActivityToolExecutionResponse(ToolExecutionOutcome Outcome, bool Executed, Guid? ExecutionId);
