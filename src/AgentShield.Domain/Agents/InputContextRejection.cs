namespace AgentShield.Domain.Agents;

/// <summary>
/// Why the input security event a tool call referenced cannot stand for the call's input. Any of these blocks the call: a
/// decision AgentShield cannot verify is never taken on the caller's word.
/// </summary>
public enum InputContextRejection
{
    /// <summary>No firewall analysis with that security event is held (never made, or no longer held).</summary>
    NotFound = 1,

    /// <summary>Another client submitted that input: a client can only reference its own analyses.</summary>
    OtherClient = 2,

    /// <summary>The analysis belongs to another trace (correlation ID) than the tool call.</summary>
    OtherTrace = 3,

    /// <summary>The analysis is older than the time a tool call may reference it.</summary>
    Expired = 4,
}
