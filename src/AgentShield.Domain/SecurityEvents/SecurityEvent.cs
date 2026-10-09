using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.Threats;

namespace AgentShield.Domain.SecurityEvents;

/// <summary>
/// Audit record of one firewall analysis: what was decided, why, and how it can be traced.
/// </summary>
/// <remarks>
/// Deliberately contains no analysed content — only its length — so it can be logged and, later, persisted without
/// becoming a store of user prompts or secrets. <see cref="Id"/> identifies the event; <see cref="CorrelationId"/>
/// traces the request that raised it. They are different things (see <see cref="SecurityEventId"/>).
/// </remarks>
public sealed record SecurityEvent
{
    public SecurityEvent(
        SecurityEventId id,
        string correlationId,
        DateTimeOffset occurredAt,
        PolicyDecision decision,
        RiskAssessment risk,
        IReadOnlyList<ThreatFinding> findings,
        int inputLength,
        TimeSpan duration)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(correlationId);
        ArgumentNullException.ThrowIfNull(decision);
        ArgumentNullException.ThrowIfNull(risk);
        ArgumentNullException.ThrowIfNull(findings);
        ArgumentOutOfRangeException.ThrowIfNegative(inputLength);
        ArgumentOutOfRangeException.ThrowIfLessThan(duration, TimeSpan.Zero);

        if (id == default)
        {
            throw new ArgumentException("A security event requires an identifier.", nameof(id));
        }

        Id = id;
        CorrelationId = correlationId;
        OccurredAt = occurredAt;
        Decision = decision;
        Risk = risk;
        Findings = findings;
        InputLength = inputLength;
        Duration = duration;
    }

    public SecurityEventId Id { get; }

    public string CorrelationId { get; }

    public DateTimeOffset OccurredAt { get; }

    public PolicyDecision Decision { get; }

    public RiskAssessment Risk { get; }

    public IReadOnlyList<ThreatFinding> Findings { get; }

    /// <summary>Length of the original input in UTF-16 code units.</summary>
    public int InputLength { get; }

    /// <summary>Time spent analysing (normalisation to decision).</summary>
    public TimeSpan Duration { get; }

    /// <summary>
    /// What AI-assisted analysis contributed (status, provider, model, duration, finding count).
    /// <see cref="AiAnalysisSummary.Disabled"/> unless set.
    /// </summary>
    public AiAnalysisSummary AiAnalysis
    {
        get;
        init
        {
            ArgumentNullException.ThrowIfNull(value);
            field = value;
        }
    } = AiAnalysisSummary.Disabled;
}
