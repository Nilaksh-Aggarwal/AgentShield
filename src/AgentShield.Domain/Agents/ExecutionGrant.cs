using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Domain.Agents;

/// <summary>
/// Exactly what one execution grant authorises: this agent, this tool action under this capability, within this gateway
/// request (its security event and correlation ID). Nothing else.
/// </summary>
/// <param name="SecurityEventId">The gateway request's security event (the audit record the grant belongs to).</param>
/// <param name="CorrelationId">The request that asked for the execution.</param>
/// <param name="Agent">The agent the gateway acts for (from the authenticated caller, never from the request body).</param>
/// <param name="Tool">The tool.</param>
/// <param name="Action">The action of that tool.</param>
/// <param name="Capability">The capability the action requires (the catalogue's, held by the agent).</param>
public sealed record ExecutionScope(
    SecurityEventId SecurityEventId,
    string CorrelationId,
    AgentId Agent,
    ToolId Tool,
    ActionName Action,
    Capability Capability)
{
    public SecurityEventId SecurityEventId { get; } = SecurityEventId == default
        ? throw new ArgumentException("An execution scope requires a security event.", nameof(SecurityEventId))
        : SecurityEventId;

    public string CorrelationId { get; } = string.IsNullOrWhiteSpace(CorrelationId)
        ? throw new ArgumentException("An execution scope requires a correlation ID.", nameof(CorrelationId))
        : CorrelationId;

    public AgentId Agent { get; } = Agent ?? throw new ArgumentNullException(nameof(Agent));

    public ToolId Tool { get; } = Tool ?? throw new ArgumentNullException(nameof(Tool));

    public ActionName Action { get; } = Action ?? throw new ArgumentNullException(nameof(Action));

    public Capability Capability { get; } = Capability ?? throw new ArgumentNullException(nameof(Capability));
}

/// <summary>
/// An authorization to execute one specific tool action once: issued by the gateway's execution authority after the
/// authorization boundary allowed the action, bound to its <see cref="Scope"/>, valid until <see cref="ExpiresAt"/>, and
/// signed so that it cannot be made up or altered.
/// </summary>
/// <remarks>
/// <para>A grant has no decision field: it exists only for an Allow, so there is nothing to change from Block or Review into
/// Allow. It never leaves the process: the request has no field that could carry one, and the response never contains
/// one. The <see cref="ExecutionId"/> is an identifier for the audit trail, not a credential.</para>
/// <para>Anyone can build an instance of this type; only the execution authority's key produces a valid
/// <see cref="Signature"/>, and only its ledger knows which grants are outstanding, so an instance built anywhere else, or
/// one presented a second time, executes nothing (docs/security/tool-gateway.md).</para>
/// </remarks>
public sealed record ExecutionGrant
{
    public ExecutionGrant(Guid executionId, ExecutionScope scope, DateTimeOffset issuedAt, DateTimeOffset expiresAt, string signature)
    {
        ArgumentNullException.ThrowIfNull(scope);
        ArgumentException.ThrowIfNullOrWhiteSpace(signature);

        if (executionId == Guid.Empty)
        {
            throw new ArgumentException("An execution grant requires an execution ID.", nameof(executionId));
        }

        if (expiresAt <= issuedAt)
        {
            throw new ArgumentException("An execution grant must expire after it was issued.", nameof(expiresAt));
        }

        ExecutionId = executionId;
        Scope = scope;
        IssuedAt = issuedAt;
        ExpiresAt = expiresAt;
        Signature = signature;
    }

    /// <summary>Identity of this execution (UUIDv7): the audit trail's handle on it.</summary>
    public Guid ExecutionId { get; }

    /// <summary>What the grant authorises, and nothing else.</summary>
    public ExecutionScope Scope { get; }

    public DateTimeOffset IssuedAt { get; }

    /// <summary>The grant authorises nothing at or after this instant.</summary>
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>The execution authority's signature over every other field (lower-case hex).</summary>
    public string Signature { get; }

    /// <summary>The grant without its signature: a record would print every property, and a grant is a credential.</summary>
    public override string ToString() => $"ExecutionGrant {{ ExecutionId = {ExecutionId}, ExpiresAt = {ExpiresAt:O} }}";
}

/// <summary>
/// Why the execution authority refused a grant: no tool ran. A fixed vocabulary for the audit log; the API reports only
/// that execution authorization was rejected.
/// </summary>
public enum ExecutionGrantRejection
{
    /// <summary>The signature does not match the grant: it was not issued by this authority, or was altered.</summary>
    InvalidSignature = 1,

    /// <summary>The grant was valid once but has already been used.</summary>
    AlreadyUsed = 2,

    /// <summary>The grant has expired.</summary>
    Expired = 3,

    /// <summary>The grant was issued for another agent.</summary>
    WrongAgent = 4,

    /// <summary>The grant was issued for another tool.</summary>
    WrongTool = 5,

    /// <summary>The grant was issued for another action.</summary>
    WrongAction = 6,

    /// <summary>The grant was issued under another capability.</summary>
    WrongCapability = 7,

    /// <summary>The grant belongs to another gateway request (security event or correlation ID).</summary>
    WrongRequest = 8,

    /// <summary>The grant is valid, but no tool is registered to execute the action.</summary>
    NoExecutor = 9,
}
