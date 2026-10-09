using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;

namespace AgentShield.Domain.SecurityEvents;

/// <summary>
/// Audit record of one agent action authorization: what was decided, why, about which recognised agent, tool, action and
/// capability, and how it can be traced.
/// </summary>
/// <remarks>
/// Holds no tool arguments (requests carry none), no free text and no name AgentShield does not recognise (see
/// <see cref="RecognisedAgentAction"/>). <see cref="Id"/> identifies the event; <see cref="CorrelationId"/> traces the
/// request that raised it, as for <see cref="SecurityEvent"/>.
/// </remarks>
public sealed record AgentActionEvent
{
    public AgentActionEvent(
        SecurityEventId id,
        string correlationId,
        DateTimeOffset occurredAt,
        AgentActionAuthorization authorization,
        SecurityDecision? inputDecision,
        TimeSpan duration)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(correlationId);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentOutOfRangeException.ThrowIfLessThan(duration, TimeSpan.Zero);

        if (id == default)
        {
            throw new ArgumentException("A security event requires an identifier.", nameof(id));
        }

        if (inputDecision is { } decision && !Enum.IsDefined(decision))
        {
            throw new ArgumentOutOfRangeException(nameof(inputDecision), inputDecision, "Unknown security decision.");
        }

        Id = id;
        CorrelationId = correlationId;
        OccurredAt = occurredAt;
        Authorization = authorization;
        InputDecision = inputDecision;
        Duration = duration;
    }

    public SecurityEventId Id { get; }

    public string CorrelationId { get; }

    public DateTimeOffset OccurredAt { get; }

    /// <summary>The authorization boundary's verdict, as returned to the caller.</summary>
    public AgentActionAuthorization Authorization { get; }

    /// <summary>The input decision the caller reported (evidence that could only tighten the verdict), if any.</summary>
    public SecurityDecision? InputDecision { get; }

    /// <summary>Time spent deciding.</summary>
    public TimeSpan Duration { get; }
}
