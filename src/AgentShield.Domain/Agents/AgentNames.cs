namespace AgentShield.Domain.Agents;

/// <summary>Identity of an agent (e.g. <c>support-agent</c>). Format: <see cref="AgentIdentifiers.IsValidName"/>.</summary>
/// <remarks>
/// What an agent may do comes only from its <see cref="AgentProfile"/>, which AgentShield's configuration defines. An agent
/// naming itself in a request proves nothing about its capabilities.
/// </remarks>
public sealed record AgentId
{
    public AgentId(string value)
    {
        // The message never quotes the value: it is caller-supplied until it has passed this check.
        Value = AgentIdentifiers.IsValidName(value) ? value : throw new ArgumentException("Not a valid agent ID.", nameof(value));
    }

    public string Value { get; }

    public override string ToString() => Value;
}

/// <summary>Identity of a tool an agent can call (e.g. <c>email</c>). Format: <see cref="AgentIdentifiers.IsValidName"/>.</summary>
/// <remarks>A tool is not a unit of permission: each of its actions (<see cref="ActionName"/>) has its own required
/// capability and risk.</remarks>
public sealed record ToolId
{
    public ToolId(string value)
    {
        Value = AgentIdentifiers.IsValidName(value) ? value : throw new ArgumentException("Not a valid tool ID.", nameof(value));
    }

    public string Value { get; }

    public override string ToString() => Value;
}

/// <summary>One operation of a tool (e.g. <c>send</c> of <c>email</c>). Format: <see cref="AgentIdentifiers.IsValidName"/>.</summary>
public sealed record ActionName
{
    public ActionName(string value)
    {
        Value = AgentIdentifiers.IsValidName(value) ? value : throw new ArgumentException("Not a valid action name.", nameof(value));
    }

    public string Value { get; }

    public override string ToString() => Value;
}

/// <summary>
/// A permission an agent can hold, written <c>resource:operation</c> (e.g. <c>email:send</c>). Format:
/// <see cref="AgentIdentifiers.IsValidCapability"/>.
/// </summary>
/// <remarks>
/// Capabilities are exact names, not patterns: there are no wildcards or hierarchies, so <c>email:send</c> is held only by an
/// agent granted exactly <c>email:send</c>. Not to be confused with the API client permissions of the HTTP boundary
/// (<c>firewall:analyze</c>, ...), which authorise the caller of AgentShield, not the agent the caller runs.
/// </remarks>
public sealed record Capability
{
    public Capability(string value)
    {
        Value = AgentIdentifiers.IsValidCapability(value) ? value : throw new ArgumentException("Not a valid capability.", nameof(value));
    }

    public string Value { get; }

    public override string ToString() => Value;
}
