namespace AgentShield.Domain.SecurityEvents;

/// <summary>
/// Identity of a security event (a detection, decision or audit record).
/// </summary>
/// <remarks>
/// Deliberately distinct from the request correlation ID: a correlation ID traces one HTTP request /
/// operation, while a single request may raise zero or many security events, and a security event
/// must remain identifiable long after the request that produced it.
/// </remarks>
public readonly record struct SecurityEventId
{
    private SecurityEventId(Guid value) => Value = value;

    public Guid Value { get; }

    /// <summary>Creates a new, time-ordered (UUIDv7) identifier.</summary>
    public static SecurityEventId New() => new(Guid.CreateVersion7());

    public static SecurityEventId From(Guid value)
    {
        if (value == Guid.Empty)
        {
            throw new ArgumentException("A security event ID cannot be empty.", nameof(value));
        }

        return new SecurityEventId(value);
    }

    public override string ToString() => Value.ToString();
}
