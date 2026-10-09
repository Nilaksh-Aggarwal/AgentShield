using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Security.Cryptography;
using System.Text;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Security.ToolGateway;

/// <summary>
/// The tool gateway's execution authority: issues signed, single-use, short-lived execution grants for actions the
/// authorization boundary allows, and is the only component that runs a tool, for such a grant only.
/// </summary>
/// <remarks>
/// <para><b>Unforgeable.</b> A grant is signed with HMAC-SHA256 over every field, under a 256-bit key generated in memory
/// when the authority is created (once per process). The key is never configured, logged, returned or exported; a restart
/// invalidates every grant, which is fine for grants that live <see cref="Lifetime"/> and never leave the process.</para>
/// <para><b>Single use.</b> Every issued grant is held in a ledger until it is presented; presenting it removes it
/// atomically, so of any number of concurrent presentations exactly one can run the tool, and a grant presented again is
/// refused. A grant is consumed whenever its signature is valid, even if a later check refuses it.</para>
/// <para><b>Bound.</b> A grant runs only the call it was issued for: same agent, tool, action, capability, security event and
/// correlation ID, compared exactly with the call the gateway presents, which the gateway builds from its own request.</para>
/// <para><b>Allow only.</b> <see cref="Issue"/> asks the authorization boundary itself and issues nothing unless it allows
/// the request. The grant has no decision field to alter.</para>
/// <para>The ledger is bounded (<see cref="MaxOutstandingGrants"/>): expired grants are purged whenever a grant is issued,
/// and issuing beyond the bound fails the request (500) rather than evicting a live grant. In normal operation a grant is
/// presented a few milliseconds after it is issued, so the ledger holds about one grant per request in flight.</para>
/// </remarks>
internal sealed class ExecutionGrantAuthority : IToolExecutionAuthority, ISingletonService
{
    /// <summary>How long a grant authorises its execution.</summary>
    public static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(30);

    /// <summary>The most grants that can be outstanding (issued, not yet presented or expired) at once.</summary>
    public const int MaxOutstandingGrants = 4_096;

    // Domain separation: a signature over these bytes means nothing in any other protocol.
    private const string SignatureContext = "AgentShield.ExecutionGrant.v1";

    private readonly IAgentActionAuthorizer _authorizer;
    private readonly IToolApprovalStore _approvals;
    private readonly TimeProvider _timeProvider;
    private readonly FrozenDictionary<(ToolId Tool, ActionName Action), IToolExecutor> _executors;
    private readonly byte[] _key = RandomNumberGenerator.GetBytes(32);
    private readonly ConcurrentDictionary<Guid, ExecutionGrant> _outstanding = new();

    public ExecutionGrantAuthority(IAgentActionAuthorizer authorizer, IToolApprovalStore approvals, IEnumerable<IToolExecutor> executors, TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(authorizer);
        ArgumentNullException.ThrowIfNull(approvals);
        ArgumentNullException.ThrowIfNull(executors);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _authorizer = authorizer;
        _approvals = approvals;
        _timeProvider = timeProvider;

        // Two executors for one action would make "which tool runs" ambiguous: a composition error.
        var byAction = new Dictionary<(ToolId, ActionName), IToolExecutor>();
        foreach (var executor in executors)
        {
            if (!byAction.TryAdd((executor.Tool, executor.Action), executor))
            {
                throw new InvalidOperationException("Several tool executors are registered for one tool action.");
            }
        }

        _executors = byAction.ToFrozenDictionary();
    }

    /// <summary>Grants issued and neither presented nor purged yet.</summary>
    public int OutstandingCount => _outstanding.Count;

    public ExecutionGrant? Issue(AgentActionRequest request, SecurityEventId securityEventId, string correlationId, Guid? approvalId = null)
    {
        ArgumentNullException.ThrowIfNull(request);

        // Not the caller's word for it: the boundary decides again, deterministically, from the same trusted data. A Review is
        // granted only with a person's approval of this agent's action that this very request used (the store's record, not
        // the gateway's say-so); a Block never.
        var decision = _authorizer.Authorize(request).Decision;
        var permitted = decision switch
        {
            SecurityDecision.Allow => true,
            SecurityDecision.Review => approvalId is { } approval && UsedFor(approval, request, securityEventId),
            _ => false,
        };
        if (!permitted)
        {
            return null;
        }

        var scope = new ExecutionScope(securityEventId, correlationId, request.Agent, request.Tool, request.Action, request.Capability);
        var issuedAt = _timeProvider.GetUtcNow();
        var expiresAt = issuedAt + Lifetime;
        var executionId = Guid.CreateVersion7(issuedAt);
        var grant = new ExecutionGrant(executionId, scope, issuedAt, expiresAt, Sign(executionId, scope, issuedAt, expiresAt));

        Purge(issuedAt);
        if (_outstanding.Count >= MaxOutstandingGrants)
        {
            throw new InvalidOperationException("Too many execution grants are outstanding.");
        }

        if (!_outstanding.TryAdd(executionId, grant))
        {
            throw new InvalidOperationException("An execution ID was issued twice.");
        }

        return grant;
    }

    /// <summary>Whether the approval was used by gateway request <paramref name="securityEventId"/> for exactly this agent's action.</summary>
    private bool UsedFor(Guid approvalId, AgentActionRequest request, SecurityEventId securityEventId) =>
        _approvals.Find(approvalId) is { Status: ToolApprovalStatus.Used, UsedBy: { } usedBy } approval
        && usedBy == securityEventId
        && approval.Binding.Agent == request.Agent
        && string.Equals(approval.Binding.Client, request.Caller, StringComparison.Ordinal)
        && approval.Binding.Tool == request.Tool
        && approval.Binding.Action == request.Action
        && approval.Binding.Capability == request.Capability;

    public async ValueTask<ToolExecutionAttempt> ExecuteAsync(ExecutionGrant grant, ToolCall call, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(grant);
        ArgumentNullException.ThrowIfNull(call);

        if (Redeem(grant, call.Scope) is { } rejection)
        {
            return ToolExecutionAttempt.Refused(rejection);
        }

        if (!_executors.TryGetValue((call.Scope.Tool, call.Scope.Action), out var executor))
        {
            return ToolExecutionAttempt.Refused(ExecutionGrantRejection.NoExecutor);
        }

        // The grant is consumed: the tool runs at most once for it, whatever happens next.
        var output = await executor.ExecuteAsync(call.Arguments, cancellationToken);
        return ToolExecutionAttempt.Ran(output);
    }

    /// <summary>Verifies and consumes <paramref name="grant"/> for <paramref name="expected"/>; the reason it is refused, if it is.</summary>
    private ExecutionGrantRejection? Redeem(ExecutionGrant grant, ExecutionScope expected)
    {
        // 1. Only this authority's key signs: a made-up or altered grant is refused without touching the ledger.
        if (!HasValidSignature(grant))
        {
            return ExecutionGrantRejection.InvalidSignature;
        }

        // 2. Single use: removing the ledger entry is atomic, so only one presentation of a grant can get past here.
        var consumed = _outstanding.TryRemove(new KeyValuePair<Guid, ExecutionGrant>(grant.ExecutionId, grant));

        // 3. Expiry (checked after consuming, so an expired grant leaves the ledger too).
        if (_timeProvider.GetUtcNow() >= grant.ExpiresAt)
        {
            return ExecutionGrantRejection.Expired;
        }

        if (!consumed)
        {
            return ExecutionGrantRejection.AlreadyUsed;
        }

        // 4. Exactly the call it was issued for.
        var scope = grant.Scope;
        if (scope.Agent != expected.Agent)
        {
            return ExecutionGrantRejection.WrongAgent;
        }

        if (scope.Tool != expected.Tool)
        {
            return ExecutionGrantRejection.WrongTool;
        }

        if (scope.Action != expected.Action)
        {
            return ExecutionGrantRejection.WrongAction;
        }

        if (scope.Capability != expected.Capability)
        {
            return ExecutionGrantRejection.WrongCapability;
        }

        if (scope.SecurityEventId != expected.SecurityEventId || !string.Equals(scope.CorrelationId, expected.CorrelationId, StringComparison.Ordinal))
        {
            return ExecutionGrantRejection.WrongRequest;
        }

        return null;
    }

    private void Purge(DateTimeOffset now)
    {
        foreach (var (executionId, grant) in _outstanding)
        {
            if (now >= grant.ExpiresAt)
            {
                _outstanding.TryRemove(new KeyValuePair<Guid, ExecutionGrant>(executionId, grant));
            }
        }
    }

    private string Sign(Guid executionId, ExecutionScope scope, DateTimeOffset issuedAt, DateTimeOffset expiresAt) =>
        Convert.ToHexStringLower(HMACSHA256.HashData(_key, Payload(executionId, scope, issuedAt, expiresAt)));

    private bool HasValidSignature(ExecutionGrant grant)
    {
        var expected = HMACSHA256.HashData(_key, Payload(grant.ExecutionId, grant.Scope, grant.IssuedAt, grant.ExpiresAt));
        return TryParseSignature(grant.Signature) is { } presented && CryptographicOperations.FixedTimeEquals(expected, presented);
    }

    private static byte[]? TryParseSignature(string signature)
    {
        if (signature.Length != HMACSHA256.HashSizeInBytes * 2)
        {
            return null;
        }

        try
        {
            return Convert.FromHexString(signature);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// The signed bytes: a context label, then every field of the grant in a fixed order, strings length-prefixed (so no
    /// two different grants encode to the same bytes) and instants as UTC ticks (the same instant compares equal whatever
    /// its offset, as in <see cref="DateTimeOffset.Equals(DateTimeOffset)"/>).
    /// </summary>
    private static byte[] Payload(Guid executionId, ExecutionScope scope, DateTimeOffset issuedAt, DateTimeOffset expiresAt)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write(SignatureContext);
            writer.Write(executionId.ToByteArray());
            writer.Write(scope.SecurityEventId.Value.ToByteArray());
            writer.Write(scope.CorrelationId);
            writer.Write(scope.Agent.Value);
            writer.Write(scope.Tool.Value);
            writer.Write(scope.Action.Value);
            writer.Write(scope.Capability.Value);
            writer.Write(issuedAt.UtcTicks);
            writer.Write(expiresAt.UtcTicks);
        }

        return stream.ToArray();
    }
}
