using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Domain.Threats;

namespace AgentShield.Application.Activity;

/// <summary>
/// What the security activity history keeps of one security event: metadata for operators, never content.
/// </summary>
/// <remarks>
/// <para>Built only by <see cref="FromSecurityEvent"/> (an input analysis), <see cref="FromAgentActionEvent"/> (an agent
/// action authorization) or <see cref="FromToolGatewayEvent"/> (a tool execution request), from the event published after
/// the decision was made. It repeats that decision and risk; it never computes a score, a level or a decision of its own,
/// and nothing that reads it can change the decision that was returned.</para>
/// <para>Holds no input, nothing decoded from it, no prompt or provider response, no rule IDs, detector identities or
/// match counts (audit data, logged only), no AI failure reason (see <see cref="ActivityAiStatus"/>), no tool arguments and
/// no tool result. The only text fields are the correlation ID, which the API accepts only as at most 64 characters of
/// <c>[A-Za-z0-9._:-]</c> or generates itself, finding codes, which are fixed identifiers, and the agent, tool, action and
/// capability names of an agent action, which come only from AgentShield's own configuration (a name the caller made up
/// is kept as <see langword="null"/>, see <see cref="RecognisedAgentAction"/>).</para>
/// <para>Kind-specific fields are <see langword="null"/> for the other kinds: agent actions and tool executions have no
/// findings, no AI analysis and no risk score; an input analysis has no agent action; only a tool execution has
/// <see cref="ToolExecution"/>.</para>
/// </remarks>
public sealed record SecurityActivityRecord
{
    private SecurityActivityRecord(
        Guid securityEventId,
        string correlationId,
        DateTimeOffset occurredAt,
        SecurityActivityKind kind,
        SecurityDecision decision,
        ActivityRisk risk,
        IReadOnlyList<ActivityFinding> findings,
        ActivityAiStatus? aiAnalysis,
        ActivityAgentAction? agentAction,
        ActivityToolExecution? toolExecution)
    {
        SecurityEventId = securityEventId;
        CorrelationId = correlationId;
        OccurredAt = occurredAt;
        Kind = kind;
        Decision = decision;
        Risk = risk;
        Findings = findings;
        AiAnalysis = aiAnalysis;
        AgentAction = agentAction;
        ToolExecution = toolExecution;
    }

    /// <summary>Identity of the security event (its audit log entry carries the same ID).</summary>
    public Guid SecurityEventId { get; }

    /// <summary>The request that raised the event.</summary>
    public string CorrelationId { get; }

    public DateTimeOffset OccurredAt { get; }

    public SecurityActivityKind Kind { get; }

    /// <summary>The decision returned to the caller (by the policy engine or the agent action authorization boundary).</summary>
    public SecurityDecision Decision { get; }

    /// <summary>The risk the decision was based on.</summary>
    public ActivityRisk Risk { get; }

    /// <summary>The fused findings behind an input analysis's decision, most severe first. Empty for an agent action.</summary>
    public IReadOnlyList<ActivityFinding> Findings { get; }

    /// <summary>What AI-assisted analysis contributed to an input analysis; <see langword="null"/> for an agent action.</summary>
    public ActivityAiStatus? AiAnalysis { get; }

    /// <summary>The recognised agent action and the authorization boundary's reason; <see langword="null"/> for an input analysis.</summary>
    public ActivityAgentAction? AgentAction { get; }

    /// <summary>How the tool gateway handled a tool execution request; <see langword="null"/> for the other kinds.</summary>
    public ActivityToolExecution? ToolExecution { get; }

    /// <summary>The activity record of an analysis, taken from its final security event.</summary>
    public static SecurityActivityRecord FromSecurityEvent(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        return new SecurityActivityRecord(
            securityEvent.Id.Value,
            securityEvent.CorrelationId,
            securityEvent.OccurredAt,
            SecurityActivityKind.InputAnalysis,
            securityEvent.Decision.Decision,
            new ActivityRisk(securityEvent.Risk.Level, securityEvent.Risk.Score),
            [.. securityEvent.Findings.Select(finding => new ActivityFinding(finding.Code, finding.Category, finding.Severity))],
            Summarise(securityEvent.AiAnalysis.Status),
            agentAction: null,
            toolExecution: null);
    }

    /// <summary>The activity record of an agent action authorization, taken from its final event.</summary>
    public static SecurityActivityRecord FromAgentActionEvent(AgentActionEvent agentActionEvent)
    {
        ArgumentNullException.ThrowIfNull(agentActionEvent);

        var authorization = agentActionEvent.Authorization;
        var recognised = authorization.Recognised;

        return new SecurityActivityRecord(
            agentActionEvent.Id.Value,
            agentActionEvent.CorrelationId,
            agentActionEvent.OccurredAt,
            SecurityActivityKind.AgentActionAuthorization,
            authorization.Decision,
            new ActivityRisk(authorization.Risk, Score: null),
            findings: [],
            aiAnalysis: null,
            new ActivityAgentAction(
                recognised.Agent?.Value,
                recognised.Tool?.Value,
                recognised.Action?.Value,
                recognised.Capability?.Value,
                authorization.Reason),
            toolExecution: null);
    }

    /// <summary>
    /// The activity record of a tool gateway request, taken from its last audit entry (Completed, Rejected or Failed): one
    /// record per request, never one per stage.
    /// </summary>
    public static SecurityActivityRecord FromToolGatewayEvent(ToolGatewayEvent toolGatewayEvent)
    {
        ArgumentNullException.ThrowIfNull(toolGatewayEvent);

        if (!toolGatewayEvent.IsTerminal)
        {
            throw new ArgumentException("Only the last entry of a tool gateway request is recorded in the activity history.", nameof(toolGatewayEvent));
        }

        // A terminal entry always carries the boundary's verdict and the outcome (ToolGatewayEvent's transitions).
        var authorization = toolGatewayEvent.Authorization!;
        var recognised = authorization.Recognised;
        var outcome = toolGatewayEvent.Outcome!.Value;

        return new SecurityActivityRecord(
            toolGatewayEvent.Id.Value,
            toolGatewayEvent.CorrelationId,
            toolGatewayEvent.OccurredAt,
            SecurityActivityKind.ToolExecution,
            ToolExecutionOutcomes.DecisionFor(outcome),
            new ActivityRisk(authorization.Risk, Score: null),
            findings: [],
            aiAnalysis: null,
            new ActivityAgentAction(
                recognised.Agent?.Value,
                recognised.Tool?.Value,
                recognised.Action?.Value,
                recognised.Capability?.Value,
                authorization.Reason),
            new ActivityToolExecution(outcome, ToolExecutionOutcomes.ToolWasInvoked(outcome), toolGatewayEvent.ExecutionId));
    }

    // The same split as the audit log's level choice (LoggingSecurityEventSink): everything but these three is a failure.
    private static ActivityAiStatus Summarise(AiAnalysisStatus status) => status switch
    {
        AiAnalysisStatus.Disabled => ActivityAiStatus.Disabled,
        AiAnalysisStatus.Completed => ActivityAiStatus.Completed,
        AiAnalysisStatus.NotNeeded => ActivityAiStatus.NotNeeded,
        _ => ActivityAiStatus.Incomplete,
    };
}

/// <summary>The risk a decision was based on, as the activity history keeps it.</summary>
/// <param name="Level">Risk level: of the analysed input, or of the agent action.</param>
/// <param name="Score">The input's prototype risk score (0–100); <see langword="null"/> for an agent action, whose risk is a
/// classification without a score.</param>
public sealed record ActivityRisk(RiskLevel Level, int? Score);

/// <summary>A finding as the activity history keeps it: what was found and how severe it is, not how it was found.</summary>
/// <param name="Code">Stable identifier of what was found (<c>Area.Reason</c>), as the analysis response returns it.</param>
/// <param name="Category">Kind of attack (or <see cref="ThreatCategory.InconclusiveAnalysis"/> for a safeguard).</param>
/// <param name="Severity">Harm indicated by this finding alone.</param>
public sealed record ActivityFinding(string Code, ThreatCategory Category, ThreatSeverity Severity);

/// <summary>
/// An agent action as the activity history keeps it: recognised names and the reason code, never arguments or free text.
/// </summary>
/// <param name="AgentId">The configured agent; <see langword="null"/> when the request named an unknown agent.</param>
/// <param name="Tool">The catalogued tool; <see langword="null"/> when unknown.</param>
/// <param name="Action">The catalogued action of that tool; <see langword="null"/> when unknown.</param>
/// <param name="Capability">The capability the agent claimed, when the catalogue knows it; otherwise <see langword="null"/>.</param>
/// <param name="Reason">Why the boundary decided as it did.</param>
public sealed record ActivityAgentAction(string? AgentId, string? Tool, string? Action, string? Capability, AgentActionReason Reason);

/// <summary>
/// How the tool gateway handled one execution request, as the activity history keeps it: never the arguments, the tool's
/// result, the argument rule that was broken or why a grant was refused (those stay in the audit log).
/// </summary>
/// <param name="Outcome">How the request ended.</param>
/// <param name="Executed">Whether the tool was invoked (also when it then failed).</param>
/// <param name="ExecutionId">The execution grant's ID when one was issued; <see langword="null"/> otherwise.</param>
public sealed record ActivityToolExecution(ToolExecutionOutcome Outcome, bool Executed, Guid? ExecutionId);
