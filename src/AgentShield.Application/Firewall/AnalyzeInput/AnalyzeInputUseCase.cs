using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Abstractions.Context;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Application.Common.Events;
using AgentShield.Application.Common.Results;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Domain.Threats;

namespace AgentShield.Application.Firewall.AnalyzeInput;

/// <summary>
/// Orchestrates the firewall pipeline. Owns no security rules itself: each stage is a port implemented in the Security
/// layer, and the policy engine makes the decision. AI-assisted analysis only contributes findings, which are fused with
/// the detectors' findings before risk and policy.
/// </summary>
internal sealed class AnalyzeInputUseCase(
    IInputNormalizer normalizer,
    IEnumerable<IThreatDetector> detectors,
    IFindingAggregator findingAggregator,
    IAiAssistedAnalysis aiAnalysis,
    IRiskEngine riskEngine,
    IPolicyEngine policyEngine,
    IEnumerable<ISecurityEventSink> securityEventSinks,
    ICorrelationContext correlationContext,
    TimeProvider timeProvider) : IAnalyzeInputUseCase, IScopedService
{
    public async Task<Result<AnalysisResponse>> ExecuteAsync(AnalyzeInputRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        var text = request.Input ?? throw new ArgumentException("The request must be validated before analysis.", nameof(request));

        var started = timeProvider.GetTimestamp();

        var input = normalizer.Normalize(text);

        var rawFindings = new List<ThreatFinding>();
        foreach (var detector in detectors)
        {
            cancellationToken.ThrowIfCancellationRequested();
            rawFindings.AddRange(detector.Detect(input));
        }

        // The AI stage sees the fused deterministic findings as context and can only add findings. It runs after
        // detection, so a slow or failing provider never changes what the detectors found.
        var deterministicFindings = findingAggregator.Aggregate(rawFindings);
        var ai = await aiAnalysis.AnalyzeAsync(input, deterministicFindings, cancellationToken);

        // Duplicates fused and order fixed here, so risk, policy, the event and the response all see the same list and
        // none of them depends on detector registration order or on which stage reported a finding.
        var findings = findingAggregator.Aggregate([.. deterministicFindings, .. ai.Findings]);
        var risk = riskEngine.Assess(findings);
        var decision = policyEngine.Decide(risk, findings);
        var duration = timeProvider.GetElapsedTime(started);

        var securityEvent = new SecurityEvent(
            SecurityEventId.New(),
            correlationContext.CorrelationId,
            timeProvider.GetUtcNow(),
            decision,
            risk,
            findings,
            text.Length,
            duration)
        {
            AiAnalysis = ai.Summary,
        };

        await PublishAsync(securityEvent, cancellationToken);

        return new AnalysisResponse(
            securityEvent.Id.Value,
            decision.Decision,
            decision.Reason,
            new RiskResponse(risk.Level, risk.Score),
            findings
                .Select(finding => new FindingResponse(
                    finding.Code,
                    finding.Category,
                    finding.Severity,
                    finding.Confidence,
                    finding.Description))
                .ToArray(),
            Math.Round(duration.TotalMilliseconds, 3));
    }

    /// <summary>
    /// Gives the finished event to every sink (audit log, activity history), each after the decision was made, so none can
    /// change it. Every sink is tried even when one fails, so a failing sink never costs another its record; a failure is
    /// then raised, not swallowed, and the analysis fails closed: no decision is returned that was not recorded.
    /// </summary>
    private Task PublishAsync(SecurityEvent securityEvent, CancellationToken cancellationToken)
        => EventSinks.PublishToEveryAsync(securityEventSinks, securityEvent, static (sink, entry, token) => sink.PublishAsync(entry, token), "Security event sinks failed to record the event.", cancellationToken);
}
