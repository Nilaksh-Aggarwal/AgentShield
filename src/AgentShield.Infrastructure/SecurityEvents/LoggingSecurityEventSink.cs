using System.Diagnostics.Metrics;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using Microsoft.Extensions.Logging;

namespace AgentShield.Infrastructure.SecurityEvents;

/// <summary>
/// Records security events as one structured log entry each (Serilog sinks carry them onwards). This is the audit
/// trail until persistence exists.
/// </summary>
/// <remarks>
/// <para>The entry has identifiers, the decision, risk, finding codes, every rule ID (including evidence fused from
/// duplicate findings), detector identities, input length, duration and what AI-assisted analysis contributed (status,
/// provider, model, finding count, duration), but never the input, anything decoded from it, a prompt or a provider
/// response.</para>
/// <para>Allowed inputs are logged at Information; Review and Block at Warning so they stand out. An Allow is also a
/// Warning when AI analysis failed, because that decision was made without the AI signal. The API refuses to start
/// outside Development when the log level would hide these entries (<see cref="AuditLevel"/>).</para>
/// <para>Every event is also counted in the <c>agentshield.security_events</c> metric, tagged with its decision, whether or
/// not the log entry is written.</para>
/// </remarks>
internal sealed partial class LoggingSecurityEventSink : ISecurityEventSink, ISingletonService
{
    public const string MeterName = "AgentShield.SecurityEvents";
    public const string DecisionsInstrument = "agentshield.security_events";
    public const string DecisionTag = "decision";

    /// <summary>The lowest level a security event is logged at (an Allow with a working or absent AI analysis).</summary>
    public const LogLevel AuditLevel = LogLevel.Information;

    private readonly ILogger<LoggingSecurityEventSink> _logger;
    private readonly Counter<long> _decisions;

    public LoggingSecurityEventSink(ILogger<LoggingSecurityEventSink> logger, IMeterFactory meterFactory)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(meterFactory);

        _logger = logger;
        _decisions = meterFactory.Create(MeterName).CreateCounter<long>(
            DecisionsInstrument,
            unit: "{event}",
            description: "Security events published, by decision; counted whether or not the audit log entry is written.");
    }

    public ValueTask PublishAsync(SecurityEvent securityEvent, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        var (decision, risk, findings, ai) = (securityEvent.Decision, securityEvent.Risk, securityEvent.Findings, securityEvent.AiAnalysis);
        // NotNeeded is not a failure: the AI was skipped because the deterministic decision was already Block.
        var aiFailed = ai.Status is not (AiAnalysisStatus.Disabled or AiAnalysisStatus.Completed or AiAnalysisStatus.NotNeeded);
        var level = decision.Decision == SecurityDecision.Allow && !aiFailed ? LogLevel.Information : LogLevel.Warning;

        // Counted before, and whatever happens to, the log entry: a disabled level or a failing log sink loses the entry but
        // never the count, so decisions that left no audit record stay visible (the log is the only audit store so far).
        _decisions.Add(1, new KeyValuePair<string, object?>(DecisionTag, decision.Decision.ToString()));
        if (!_logger.IsEnabled(level))
        {
            return ValueTask.CompletedTask;
        }

        var findingCodes = findings.Select(finding => finding.Code).ToArray();
        var evidence = findings.SelectMany(finding => finding.AllEvidence).ToArray();
        var ruleIds = evidence.Select(item => item.RuleId).ToArray();
        var detectors = evidence.Select(item => item.Detector).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var securityEventId = securityEvent.Id.Value;
        var durationMs = Math.Round(securityEvent.Duration.TotalMilliseconds, 3);
        var aiDurationMs = Math.Round(ai.Duration.TotalMilliseconds, 3);

        LogSecurityEvent(
            _logger,
            level,
            securityEventId,
            securityEvent.CorrelationId,
            decision.Decision,
            decision.RuleCode,
            risk.Level,
            risk.Score,
            findings.Count,
            findingCodes,
            ruleIds,
            detectors,
            ai.Status,
            ai.Provider,
            ai.Model,
            ai.FindingCount,
            aiDurationMs,
            securityEvent.InputLength,
            durationMs);

        return ValueTask.CompletedTask;
    }

    [LoggerMessage(
        EventId = 1000,
        EventName = "SecurityEvent",
        Message = "Security event {SecurityEventId} (correlation {CorrelationId}): {Decision} by {PolicyRule}; risk {RiskLevel} "
            + "score {RiskScore}; {FindingCount} finding(s) {FindingCodes} from rules {RuleIds} of detectors {Detectors}; "
            + "AI analysis {AiStatus} by {AiProvider} {AiModel} with {AiFindingCount} finding(s) in {AiDurationMs} ms; "
            + "input length {InputLength}; analysed in {DurationMs} ms")]
    private static partial void LogSecurityEvent(
        ILogger logger,
        LogLevel level,
        Guid securityEventId,
        string correlationId,
        SecurityDecision decision,
        string policyRule,
        RiskLevel riskLevel,
        int riskScore,
        int findingCount,
        string[] findingCodes,
        string[] ruleIds,
        string[] detectors,
        AiAnalysisStatus aiStatus,
        string? aiProvider,
        string? aiModel,
        int aiFindingCount,
        double aiDurationMs,
        int inputLength,
        double durationMs);
}
