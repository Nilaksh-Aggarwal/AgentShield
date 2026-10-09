using System.Diagnostics.Metrics;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using Microsoft.Extensions.Logging;

namespace AgentShield.Infrastructure.SecurityEvents;

/// <summary>
/// Records agent action authorizations as one structured log entry each: the audit trail of the authorization boundary,
/// next to the firewall's security events (<see cref="LoggingSecurityEventSink"/>).
/// </summary>
/// <remarks>
/// <para>The entry has the identifiers, decision, reason, risk, the recognised agent, tool, action and claimed capability,
/// the reported input decision and the duration. A name AgentShield does not recognise is logged as <see cref="Unknown"/>,
/// never verbatim, so a caller cannot write text of its choosing into the audit log. There are no tool arguments to log.</para>
/// <para>Allow is logged at Information, Review and Block at Warning. Outside Development the API refuses to start when the
/// log level would hide these entries (<see cref="AuditLevel"/>). Every event is also counted in the
/// <c>agentshield.agent_action_events</c> metric, tagged with its decision, whether or not the entry is written.</para>
/// </remarks>
internal sealed partial class LoggingAgentActionEventSink : IAgentActionEventSink, ISingletonService
{
    public const string DecisionsInstrument = "agentshield.agent_action_events";

    /// <summary>The lowest level an agent action event is logged at (an Allow).</summary>
    public const LogLevel AuditLevel = LogLevel.Information;

    /// <summary>What is logged in place of a name AgentShield does not recognise.</summary>
    public const string Unknown = "(unknown)";

    private readonly ILogger<LoggingAgentActionEventSink> _logger;
    private readonly Counter<long> _decisions;

    public LoggingAgentActionEventSink(ILogger<LoggingAgentActionEventSink> logger, IMeterFactory meterFactory)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(meterFactory);

        _logger = logger;
        _decisions = meterFactory.Create(LoggingSecurityEventSink.MeterName).CreateCounter<long>(
            DecisionsInstrument,
            unit: "{event}",
            description: "Agent action authorizations, by decision; counted whether or not the audit log entry is written.");
    }

    public ValueTask PublishAsync(AgentActionEvent agentActionEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(agentActionEvent);

        var authorization = agentActionEvent.Authorization;
        var level = authorization.Decision == SecurityDecision.Allow ? LogLevel.Information : LogLevel.Warning;

        // Counted first, whatever happens to the log entry (as for the firewall's security events, H-07).
        _decisions.Add(1, new KeyValuePair<string, object?>(LoggingSecurityEventSink.DecisionTag, authorization.Decision.ToString()));
        if (!_logger.IsEnabled(level))
        {
            return ValueTask.CompletedTask;
        }

        var recognised = authorization.Recognised;
        var inputDecision = agentActionEvent.InputDecision?.ToString() ?? "(none)";
        var durationMs = Math.Round(agentActionEvent.Duration.TotalMilliseconds, 3);
        LogAgentActionEvent(
            _logger,
            level,
            agentActionEvent.Id.Value,
            agentActionEvent.CorrelationId,
            authorization.Decision,
            authorization.Reason,
            authorization.Risk,
            recognised.Agent?.Value ?? Unknown,
            recognised.Tool?.Value ?? Unknown,
            recognised.Action?.Value ?? Unknown,
            recognised.Capability?.Value ?? Unknown,
            inputDecision,
            durationMs);

        return ValueTask.CompletedTask;
    }

    [LoggerMessage(
        EventId = 1001,
        EventName = "AgentActionEvent",
        Message = "Agent action event {SecurityEventId} (correlation {CorrelationId}): {Decision} ({AgentActionReason}); risk {RiskLevel}; "
            + "agent {AgentId} tool {Tool} action {ToolAction} capability {Capability}; input decision {InputDecision}; decided in {DurationMs} ms")]
    private static partial void LogAgentActionEvent(
        ILogger logger,
        LogLevel level,
        Guid securityEventId,
        string correlationId,
        SecurityDecision decision,
        AgentActionReason agentActionReason,
        RiskLevel riskLevel,
        string agentId,
        string tool,
        string toolAction,
        string capability,
        string inputDecision,
        double durationMs);
}
