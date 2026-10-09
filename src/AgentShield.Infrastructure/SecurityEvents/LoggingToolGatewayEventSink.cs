using System.Diagnostics.Metrics;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.SecurityEvents;
using Microsoft.Extensions.Logging;

namespace AgentShield.Infrastructure.SecurityEvents;

/// <summary>
/// Records every stage of a tool gateway request as one structured log entry: the audit trail of the tool gateway, next to
/// the firewall's security events and the agent action authorizations.
/// </summary>
/// <remarks>
/// <para>One entry per stage (<see cref="ToolGatewayEventType"/>), all with the request's security event ID: identifiers,
/// the trusted agent, the recognised tool, action and capability, the decision and the boundary's reason, the risk, the
/// outcome, the execution ID, and fixed-vocabulary codes for a rejected argument or grant. A name AgentShield does not
/// recognise is logged as <see cref="Unknown"/>, never verbatim; a field not decided yet at that stage is
/// <see cref="Pending"/>. Never the tool arguments, the tool's result or a grant's signature.</para>
/// <para>Levels: a request, an Allow, a start and a completion at Information; a Block, a Review and a rejection at Warning;
/// a failed tool at Error. Outside Development the API refuses to start when the log level would hide these entries
/// (<see cref="AuditLevel"/>). Every entry is also counted in the <c>agentshield.tool_gateway_events</c> metric, tagged with
/// its stage, whether or not the entry is written.</para>
/// </remarks>
internal sealed partial class LoggingToolGatewayEventSink : IToolGatewayEventSink, ISingletonService
{
    public const string EventsInstrument = "agentshield.tool_gateway_events";
    public const string StageTag = "stage";

    /// <summary>The lowest level a tool gateway entry is logged at.</summary>
    public const LogLevel AuditLevel = LogLevel.Information;

    /// <summary>What is logged in place of a name AgentShield does not recognise.</summary>
    public const string Unknown = "(unknown)";

    /// <summary>What is logged for a field that is decided at a later stage.</summary>
    public const string Pending = "(pending)";

    /// <summary>What is logged for a field that does not apply to the entry.</summary>
    public const string None = "(none)";

    private readonly ILogger<LoggingToolGatewayEventSink> _logger;
    private readonly Counter<long> _events;

    public LoggingToolGatewayEventSink(ILogger<LoggingToolGatewayEventSink> logger, IMeterFactory meterFactory)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(meterFactory);

        _logger = logger;
        _events = meterFactory.Create(LoggingSecurityEventSink.MeterName).CreateCounter<long>(
            EventsInstrument,
            unit: "{event}",
            description: "Tool gateway audit entries, by stage; counted whether or not the audit log entry is written.");
    }

    public ValueTask PublishAsync(ToolGatewayEvent toolGatewayEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(toolGatewayEvent);

        var level = LevelOf(toolGatewayEvent.Type);

        // Counted first, whatever happens to the log entry (as for the other security events, H-07).
        _events.Add(1, new KeyValuePair<string, object?>(StageTag, toolGatewayEvent.Type.ToString()));
        if (!_logger.IsEnabled(level))
        {
            return ValueTask.CompletedTask;
        }

        var authorization = toolGatewayEvent.Authorization;
        var recognised = authorization?.Recognised;
        var undecided = authorization is null;
        var tool = Recognised(undecided, recognised?.Tool?.Value);
        var action = Recognised(undecided, recognised?.Action?.Value);
        var capability = Recognised(undecided, recognised?.Capability?.Value);
        var decision = toolGatewayEvent.Decision?.ToString() ?? Pending;
        var reason = authorization?.Reason.ToString() ?? Pending;
        var risk = authorization?.Risk.ToString() ?? Pending;
        var outcome = toolGatewayEvent.Outcome?.ToString() ?? Pending;
        var executionId = toolGatewayEvent.ExecutionId?.ToString() ?? None;
        var argumentViolation = toolGatewayEvent.ArgumentViolation?.ToString() ?? None;
        var grantRejection = toolGatewayEvent.GrantRejection?.ToString() ?? None;
        var inputDecision = toolGatewayEvent.InputDecision?.ToString() ?? None;
        var inputEventId = toolGatewayEvent.InputEventId?.ToString() ?? None;
        var inputContextRejection = toolGatewayEvent.InputContextRejection?.ToString() ?? None;
        var approvalId = toolGatewayEvent.ApprovalId?.ToString() ?? None;
        var approvalRejection = toolGatewayEvent.ApprovalRejection?.ToString() ?? None;
        var elapsedMs = Math.Round(toolGatewayEvent.Elapsed.TotalMilliseconds, 3);
        LogToolGatewayEvent(
            _logger,
            level,
            toolGatewayEvent.Type,
            toolGatewayEvent.Id.Value,
            toolGatewayEvent.CorrelationId,
            toolGatewayEvent.Agent.Value,
            tool,
            action,
            capability,
            decision,
            reason,
            risk,
            outcome,
            executionId,
            argumentViolation,
            grantRejection,
            inputDecision,
            inputEventId,
            inputContextRejection,
            approvalId,
            approvalRejection,
            elapsedMs);

        return ValueTask.CompletedTask;
    }

    /// <summary>The level of each stage: the noteworthy ones stand out.</summary>
    public static LogLevel LevelOf(ToolGatewayEventType type) => type switch
    {
        ToolGatewayEventType.ToolAuthorizationRequested
            or ToolGatewayEventType.ToolAuthorizationAllowed
            or ToolGatewayEventType.ToolExecutionStarted
            or ToolGatewayEventType.ToolExecutionCompleted => LogLevel.Information,
        ToolGatewayEventType.ToolAuthorizationBlocked
            or ToolGatewayEventType.ToolAuthorizationReviewed
            or ToolGatewayEventType.ToolExecutionRejected => LogLevel.Warning,
        ToolGatewayEventType.ToolExecutionFailed => LogLevel.Error,
        _ => throw new ArgumentOutOfRangeException(nameof(type), type, "Unknown tool gateway stage."),
    };

    // Before the boundary decided, nothing about the tool was looked at yet; after, an unrecognised name is unknown.
    private static string Recognised(bool undecided, string? name) => undecided ? Pending : name ?? Unknown;

    [LoggerMessage(
        EventId = 1002,
        EventName = "ToolGatewayEvent",
        Message = "Tool gateway {ToolGatewayStage} for security event {SecurityEventId} (correlation {CorrelationId}): agent {AgentId} "
            + "tool {Tool} action {ToolAction} capability {Capability}; decision {Decision} ({AgentActionReason}); risk {RiskLevel}; "
            + "outcome {ToolExecutionOutcome}; execution {ExecutionId}; argument violation {ArgumentViolation}; grant rejection {GrantRejection}; "
            + "input decision {InputDecision} (input event {InputEventId}, input event rejection {InputContextRejection}); "
            + "approval {ApprovalId} (approval rejection {ApprovalRejection}); after {ElapsedMs} ms")]
    private static partial void LogToolGatewayEvent(
        ILogger logger,
        LogLevel level,
        ToolGatewayEventType toolGatewayStage,
        Guid securityEventId,
        string correlationId,
        string agentId,
        string tool,
        string toolAction,
        string capability,
        string decision,
        string agentActionReason,
        string riskLevel,
        string toolExecutionOutcome,
        string executionId,
        string argumentViolation,
        string grantRejection,
        string inputDecision,
        string inputEventId,
        string inputContextRejection,
        string approvalId,
        string approvalRejection,
        double elapsedMs);
}
