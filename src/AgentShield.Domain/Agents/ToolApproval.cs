using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Domain.Agents;

/// <summary>Where a person's approval of a held tool call stands.</summary>
public enum ToolApprovalStatus
{
    /// <summary>Waiting for a person: nothing may run.</summary>
    Pending = 1,

    /// <summary>A person approved it: the exact call may run once, until the approval expires.</summary>
    Approved = 2,

    /// <summary>A person denied it (or recording the approval failed): nothing may run.</summary>
    Denied = 3,

    /// <summary>Nobody decided, or the approved call was not run, in time: nothing may run.</summary>
    Expired = 4,

    /// <summary>The approved call ran (or was presented to run) once: the approval cannot authorise anything again.</summary>
    Used = 5,
}

/// <summary>Why an approval does not authorise the call presented with it.</summary>
public enum ToolApprovalRejection
{
    NotFound = 1,
    NotApproved = 2,
    Expired = 3,
    AlreadyUsed = 4,
    WrongAgent = 5,
    WrongClient = 6,
    WrongTool = 7,
    WrongAction = 8,
    WrongCapability = 9,
    WrongArguments = 10,
    WrongInputEvent = 11,
}

/// <summary>
/// The exact tool call an approval is for: the agent (from its credential), the client that asked, the tool action and the
/// claimed capability, a digest of the arguments, and the input security event the call referenced. An approval authorises
/// this call and nothing else.
/// </summary>
/// <remarks>The arguments themselves are never kept: only their SHA-256 digest, so the same call can be recognised.</remarks>
public sealed record ToolApprovalBinding
{
    public ToolApprovalBinding(AgentId agent, string client, ToolId tool, ActionName action, Capability capability, string argumentsDigest, SecurityEventId? inputEventId)
    {
        ArgumentNullException.ThrowIfNull(agent);
        ArgumentException.ThrowIfNullOrWhiteSpace(client);
        ArgumentNullException.ThrowIfNull(tool);
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(capability);

        if (argumentsDigest is not { Length: 64 } || argumentsDigest.Any(character => !char.IsAsciiHexDigitLower(character)))
        {
            throw new ArgumentException("An approval binds the arguments by their SHA-256 digest (64 lower-case hex characters).", nameof(argumentsDigest));
        }

        if (inputEventId is { } input && input == default)
        {
            throw new ArgumentException("A referenced input security event requires an identifier.", nameof(inputEventId));
        }

        Agent = agent;
        Client = client;
        Tool = tool;
        Action = action;
        Capability = capability;
        ArgumentsDigest = argumentsDigest;
        InputEventId = inputEventId;
    }

    public AgentId Agent { get; }

    public string Client { get; }

    public ToolId Tool { get; }

    public ActionName Action { get; }

    public Capability Capability { get; }

    /// <summary>SHA-256 of the call's arguments, lower-case hex. Never shown: it could be guessed back for short arguments.</summary>
    public string ArgumentsDigest { get; }

    public SecurityEventId? InputEventId { get; }

    /// <summary>The first way <paramref name="presented"/> differs from this binding, or <see langword="null"/> when it is the same call.</summary>
    public ToolApprovalRejection? Mismatch(ToolApprovalBinding presented)
    {
        ArgumentNullException.ThrowIfNull(presented);

        return presented switch
        {
            _ when presented.Agent != Agent => ToolApprovalRejection.WrongAgent,
            _ when !string.Equals(presented.Client, Client, StringComparison.Ordinal) => ToolApprovalRejection.WrongClient,
            _ when presented.Tool != Tool => ToolApprovalRejection.WrongTool,
            _ when presented.Action != Action => ToolApprovalRejection.WrongAction,
            _ when presented.Capability != Capability => ToolApprovalRejection.WrongCapability,
            _ when !string.Equals(presented.ArgumentsDigest, ArgumentsDigest, StringComparison.Ordinal) => ToolApprovalRejection.WrongArguments,
            _ when presented.InputEventId is { } input && input != InputEventId => ToolApprovalRejection.WrongInputEvent,
            _ => null,
        };
    }

    public override string ToString() => $"ToolApprovalBinding {{ Agent = {Agent}, Tool = {Tool}, Action = {Action} }}";
}

/// <summary>
/// A person's approval of one tool call the authorization boundary held for review. Created by the tool gateway, decided by
/// a person holding the approval permission, and used at most once by the gateway for exactly the call it binds.
/// </summary>
/// <remarks>
/// <para>Metadata only: identifiers, the trusted agent and names, the boundary's risk and reason, the input decision the call
/// was held for, times and status. Never the arguments (only their digest), the input, a credential or anything the caller
/// wrote freely.</para>
/// <para>Transitions only through the methods below: Pending → Approved or Denied; Approved → Used. Pending and Approved
/// expire at <see cref="ExpiresAt"/>; nothing leaves Denied, Expired or Used.</para>
/// </remarks>
public sealed record ToolApproval
{
    private ToolApproval(
        Guid id,
        SecurityEventId requestEventId,
        string correlationId,
        ToolApprovalBinding binding,
        RiskLevel risk,
        AgentActionReason reason,
        SecurityDecision? inputDecision,
        DateTimeOffset requestedAt,
        DateTimeOffset expiresAt,
        ToolApprovalStatus status,
        DateTimeOffset? decidedAt,
        string? decidedBy,
        DateTimeOffset? usedAt,
        SecurityEventId? usedBy)
    {
        Id = id;
        RequestEventId = requestEventId;
        CorrelationId = correlationId;
        Binding = binding;
        Risk = risk;
        Reason = reason;
        InputDecision = inputDecision;
        RequestedAt = requestedAt;
        ExpiresAt = expiresAt;
        Status = status;
        DecidedAt = decidedAt;
        DecidedBy = decidedBy;
        UsedAt = usedAt;
        UsedBy = usedBy;
    }

    /// <summary>The approval's identifier: random, so it cannot be guessed. Not a credential: deciding needs the approval
    /// permission, and using it needs the agent's own credential and exactly the bound call.</summary>
    public Guid Id { get; }

    /// <summary>The security event of the gateway request that was held and created this approval.</summary>
    public SecurityEventId RequestEventId { get; }

    public string CorrelationId { get; }

    public ToolApprovalBinding Binding { get; }

    public RiskLevel Risk { get; }

    /// <summary>Why the boundary held the call: a high-risk action, or an input held for review.</summary>
    public AgentActionReason Reason { get; }

    /// <summary>The input decision the call was held under (server-verified when an input event was referenced).</summary>
    public SecurityDecision? InputDecision { get; }

    public DateTimeOffset RequestedAt { get; }

    /// <summary>When a pending approval can no longer be decided, and an approved one no longer used.</summary>
    public DateTimeOffset ExpiresAt { get; }

    /// <summary>The stored status; see <see cref="StatusAt"/> for the status at a given time (expiry included).</summary>
    public ToolApprovalStatus Status { get; }

    public DateTimeOffset? DecidedAt { get; }

    /// <summary>The configured client ID of the person's console that decided (never a key).</summary>
    public string? DecidedBy { get; }

    public DateTimeOffset? UsedAt { get; }

    /// <summary>The security event of the gateway request that used the approval.</summary>
    public SecurityEventId? UsedBy { get; }

    /// <summary>A new approval for a call the boundary held for review.</summary>
    public static ToolApproval Request(
        SecurityEventId requestEventId,
        string correlationId,
        ToolApprovalBinding binding,
        AgentActionAuthorization authorization,
        SecurityDecision? inputDecision,
        DateTimeOffset requestedAt,
        TimeSpan lifetime)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(correlationId);
        ArgumentNullException.ThrowIfNull(binding);
        ArgumentNullException.ThrowIfNull(authorization);

        if (requestEventId == default)
        {
            throw new ArgumentException("An approval requires the security event of the request it is for.", nameof(requestEventId));
        }

        if (authorization.Decision != SecurityDecision.Review)
        {
            throw new ArgumentException("Only a call the authorization boundary held for review can be approved.", nameof(authorization));
        }

        if (lifetime <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(lifetime), lifetime, "An approval must have a positive lifetime.");
        }

        if (inputDecision is { } decision && !Enum.IsDefined(decision))
        {
            throw new ArgumentOutOfRangeException(nameof(inputDecision), inputDecision, "Unknown security decision.");
        }

        return new ToolApproval(
            Guid.NewGuid(), requestEventId, correlationId, binding, authorization.Risk, authorization.Reason, inputDecision,
            requestedAt, requestedAt + lifetime, ToolApprovalStatus.Pending, decidedAt: null, decidedBy: null, usedAt: null, usedBy: null);
    }

    /// <summary>The status at <paramref name="now"/>: a pending or approved approval past its expiry is expired.</summary>
    public ToolApprovalStatus StatusAt(DateTimeOffset now) =>
        Status is ToolApprovalStatus.Pending or ToolApprovalStatus.Approved && now >= ExpiresAt ? ToolApprovalStatus.Expired : Status;

    /// <summary>A person approved the pending call.</summary>
    public ToolApproval Approve(DateTimeOffset at, string approver) => Decide(ToolApprovalStatus.Approved, at, approver);

    /// <summary>A person denied the pending call.</summary>
    public ToolApproval Deny(DateTimeOffset at, string approver) => Decide(ToolApprovalStatus.Denied, at, approver);

    /// <summary>
    /// Withdrawn whatever its state, because the approval could not be recorded: an approval the audit log does not hold must
    /// never authorise anything. Pending and approved approvals become Denied; the others stay as they are.
    /// </summary>
    public ToolApproval Revoke(DateTimeOffset at) =>
        Status is ToolApprovalStatus.Pending or ToolApprovalStatus.Approved
            ? new ToolApproval(Id, RequestEventId, CorrelationId, Binding, Risk, Reason, InputDecision, RequestedAt, ExpiresAt, ToolApprovalStatus.Denied, at, DecidedBy, UsedAt, UsedBy)
            : this;

    /// <summary>
    /// Why this approval cannot authorise <paramref name="presented"/> at <paramref name="now"/>, or <see langword="null"/> when
    /// it can: it is approved, unused, unexpired, and binds exactly that call.
    /// </summary>
    public ToolApprovalRejection? RejectionFor(ToolApprovalBinding presented, DateTimeOffset now) => StatusAt(now) switch
    {
        ToolApprovalStatus.Used => ToolApprovalRejection.AlreadyUsed,
        ToolApprovalStatus.Expired => ToolApprovalRejection.Expired,
        ToolApprovalStatus.Pending or ToolApprovalStatus.Denied => ToolApprovalRejection.NotApproved,
        _ => Binding.Mismatch(presented),
    };

    /// <summary>The approved call is being run by gateway request <paramref name="by"/>: it can never authorise anything again.</summary>
    public ToolApproval Use(ToolApprovalBinding presented, DateTimeOffset at, SecurityEventId by)
    {
        if (RejectionFor(presented, at) is { } rejection)
        {
            throw new InvalidOperationException($"The approval cannot be used: {rejection}.");
        }

        if (by == default)
        {
            throw new ArgumentException("Using an approval requires the security event of the request that uses it.", nameof(by));
        }

        return new ToolApproval(Id, RequestEventId, CorrelationId, Binding, Risk, Reason, InputDecision, RequestedAt, ExpiresAt, ToolApprovalStatus.Used, DecidedAt, DecidedBy, at, by);
    }

    private ToolApproval Decide(ToolApprovalStatus decision, DateTimeOffset at, string approver)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(approver);

        if (StatusAt(at) != ToolApprovalStatus.Pending)
        {
            throw new InvalidOperationException("Only a pending, unexpired approval can be decided.");
        }

        return new ToolApproval(Id, RequestEventId, CorrelationId, Binding, Risk, Reason, InputDecision, RequestedAt, ExpiresAt, decision, at, approver, usedAt: null, usedBy: null);
    }
}
