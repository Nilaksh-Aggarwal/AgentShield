using System.Diagnostics.Metrics;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.SecurityEvents;
using Microsoft.Extensions.Logging;

namespace AgentShield.Infrastructure.SecurityEvents;

/// <summary>
/// Writes a person's decision on a held tool call to the audit log (event 1003): the approval, the call it binds (agent,
/// tool, action, capability), its risk and reason, who decided (a configured client ID, never a key) and the traces. Never the
/// arguments or their digest. Every decision is counted in <see cref="EventsInstrument"/> whether or not the entry is written.
/// </summary>
internal sealed partial class LoggingToolApprovalEventSink : IToolApprovalEventSink, ISingletonService
{
    public const string EventsInstrument = "agentshield.tool_approval_events";
    public const string DecisionTag = "decision";

    /// <summary>The level of every approval decision: the audit trail, so outside Development it must be logged (startup check).</summary>
    public const LogLevel AuditLevel = LogLevel.Information;

    private readonly ILogger<LoggingToolApprovalEventSink> _logger;
    private readonly Counter<long> _events;

    public LoggingToolApprovalEventSink(ILogger<LoggingToolApprovalEventSink> logger, IMeterFactory meterFactory)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(meterFactory);

        _logger = logger;
        _events = meterFactory.Create(LoggingSecurityEventSink.MeterName).CreateCounter<long>(
            EventsInstrument,
            unit: "{event}",
            description: "People's decisions on held tool calls, by decision; counted whether or not the audit log entry is written.");
    }

    public ValueTask PublishAsync(ToolApprovalEvent toolApprovalEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(toolApprovalEvent);

        // Counted first, whatever happens to the log entry (as for the other audit entries, H-07).
        _events.Add(1, new KeyValuePair<string, object?>(DecisionTag, toolApprovalEvent.Type.ToString()));
        if (!_logger.IsEnabled(AuditLevel))
        {
            return ValueTask.CompletedTask;
        }

        var approval = toolApprovalEvent.Approval;
        var binding = approval.Binding;
        var approvalId = approval.Id;
        var requestEventId = approval.RequestEventId.Value;
        var heldCorrelationId = approval.CorrelationId;
        var agentId = binding.Agent.Value;
        var tool = binding.Tool.Value;
        var action = binding.Action.Value;
        var capability = binding.Capability.Value;
        var risk = approval.Risk.ToString();
        var reason = approval.Reason.ToString();
        var decidedBy = approval.DecidedBy ?? "(none)";
        var expiresAt = approval.ExpiresAt;
        LogToolApprovalEvent(
            _logger,
            toolApprovalEvent.Type,
            approvalId,
            requestEventId,
            heldCorrelationId,
            toolApprovalEvent.CorrelationId,
            agentId,
            tool,
            action,
            capability,
            risk,
            reason,
            decidedBy,
            expiresAt);

        return ValueTask.CompletedTask;
    }

    [LoggerMessage(
        EventId = 1003,
        EventName = "ToolApprovalEvent",
        Level = LogLevel.Information,
        Message = "Tool approval {ToolApprovalDecision}: approval {ApprovalId} for security event {SecurityEventId} (held in correlation "
            + "{HeldCorrelationId}, decided in correlation {CorrelationId}): agent {AgentId} tool {Tool} action {ToolAction} capability "
            + "{Capability}; risk {RiskLevel}; reason {AgentActionReason}; decided by client {ClientId}; expires {ExpiresAt}")]
    private static partial void LogToolApprovalEvent(
        ILogger logger,
        ToolApprovalEventType toolApprovalDecision,
        Guid approvalId,
        Guid securityEventId,
        string heldCorrelationId,
        string correlationId,
        string agentId,
        string tool,
        string toolAction,
        string capability,
        string riskLevel,
        string agentActionReason,
        string clientId,
        DateTimeOffset expiresAt);
}
