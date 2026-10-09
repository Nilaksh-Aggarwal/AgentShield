using AgentShield.Domain.Policy;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Abstractions.Security;

/// <summary>
/// The server's record of one firewall analysis, as a tool call may reference it: which security event, in which trace, by
/// which client, with which decision. Metadata only: never the input, a finding or anything derived from the text.
/// </summary>
public sealed record InputSecurityContext
{
    /// <summary>How long a tool call may reference an analysis.</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(10);

    public InputSecurityContext(SecurityEventId securityEventId, string correlationId, string client, SecurityDecision decision, DateTimeOffset occurredAt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(correlationId);
        ArgumentException.ThrowIfNullOrWhiteSpace(client);

        if (securityEventId == default)
        {
            throw new ArgumentException("An input security context requires its security event.", nameof(securityEventId));
        }

        if (!Enum.IsDefined(decision))
        {
            throw new ArgumentOutOfRangeException(nameof(decision), decision, "Unknown security decision.");
        }

        SecurityEventId = securityEventId;
        CorrelationId = correlationId;
        Client = client;
        Decision = decision;
        OccurredAt = occurredAt;
    }

    public SecurityEventId SecurityEventId { get; }

    /// <summary>The trace of the analysis request; a tool call must belong to the same trace.</summary>
    public string CorrelationId { get; }

    /// <summary>The configured client ID that submitted the input for analysis; only that client may reference it.</summary>
    public string Client { get; }

    /// <summary>The firewall's decision on the input: authoritative for every tool call that references this event.</summary>
    public SecurityDecision Decision { get; }

    public DateTimeOffset OccurredAt { get; }

    public DateTimeOffset ExpiresAt => OccurredAt + Lifetime;
}

/// <summary>
/// Recent firewall decisions, so a tool call can reference the analysis of its input instead of reporting the decision. In
/// memory, bounded and per process: an analysis that is no longer held cannot be referenced (the tool call is then blocked).
/// </summary>
public interface IInputSecurityContextStore
{
    ValueTask RecordAsync(InputSecurityContext context, CancellationToken cancellationToken);

    InputSecurityContext? Find(SecurityEventId securityEventId);
}
