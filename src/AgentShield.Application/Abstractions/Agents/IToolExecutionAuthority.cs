using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Abstractions.Agents;

/// <summary>
/// The tool gateway's execution authority: the only component that holds execution authority over tools. It issues signed,
/// single-use, short-lived execution grants for actions the authorization boundary allows, and runs a tool only for such a
/// grant. Implemented in the Security layer.
/// </summary>
/// <remarks>
/// <para><b>Issuing.</b> <see cref="Issue"/> does not take the caller's word for the Allow: it asks the authorization boundary
/// (<see cref="IAgentActionAuthorizer"/>) again and issues nothing unless the boundary allows exactly this request. A grant
/// has no decision field, so a Block or Review cannot be turned into one.</para>
/// <para><b>Executing.</b> <see cref="ExecuteAsync"/> verifies the grant's signature, consumes it (single use, atomically),
/// checks its expiry and that it was issued for exactly the call presented (agent, tool, action, capability, request), and
/// only then runs the registered tool, once. Any failed check runs nothing.</para>
/// <para><b>Credential boundary.</b> The signing key is generated in memory when the process starts and never leaves the
/// authority: it is not configured, logged or returned, and grants never leave the process. The agent holds only its
/// AgentShield API key, which lets it ask the gateway; it never holds anything that executes a tool.</para>
/// </remarks>
public interface IToolExecutionAuthority
{
    /// <summary>
    /// A grant to execute exactly <paramref name="request"/>'s action once, within the gateway request
    /// <paramref name="securityEventId"/> / <paramref name="correlationId"/>; <see langword="null"/> when the authorization
    /// boundary does not allow the request, unless it holds it for review and <paramref name="approvalId"/> is a person's
    /// approval of this agent's action that this very request used.
    /// </summary>
    ExecutionGrant? Issue(AgentActionRequest request, SecurityEventId securityEventId, string correlationId, Guid? approvalId = null);

    /// <summary>
    /// Verifies and consumes <paramref name="grant"/> for <paramref name="call"/>, then runs the call's tool once. A refused
    /// grant runs nothing. A failure of the tool itself propagates (the grant stays consumed).
    /// </summary>
    ValueTask<ToolExecutionAttempt> ExecuteAsync(ExecutionGrant grant, ToolCall call, CancellationToken cancellationToken);
}

/// <summary>A tool call as the gateway presents it to the execution authority: what is to run, with which arguments.</summary>
/// <param name="Scope">What the gateway asks to execute, established from its own request (never taken from the grant).</param>
/// <param name="Arguments">Arguments the action's argument policy accepted.</param>
public sealed record ToolCall(ExecutionScope Scope, ToolArguments Arguments)
{
    public ExecutionScope Scope { get; } = Scope ?? throw new ArgumentNullException(nameof(Scope));

    public ToolArguments Arguments { get; } = Arguments ?? throw new ArgumentNullException(nameof(Arguments));
}

/// <summary>What the execution authority did with a grant: ran the tool (and its output), or refused the grant.</summary>
public sealed record ToolExecutionAttempt
{
    private ToolExecutionAttempt(ToolOutput? output, ExecutionGrantRejection? rejection)
    {
        Output = output;
        Rejection = rejection;
    }

    /// <summary>The tool's output; <see langword="null"/> when the grant was refused and nothing ran.</summary>
    public ToolOutput? Output { get; }

    /// <summary>Why the grant was refused; <see langword="null"/> when the tool ran.</summary>
    public ExecutionGrantRejection? Rejection { get; }

    public bool Executed => Output is not null;

    public static ToolExecutionAttempt Ran(ToolOutput output) =>
        new(output ?? throw new ArgumentNullException(nameof(output)), rejection: null);

    public static ToolExecutionAttempt Refused(ExecutionGrantRejection rejection) =>
        Enum.IsDefined(rejection)
            ? new(output: null, rejection)
            : throw new ArgumentOutOfRangeException(nameof(rejection), rejection, "Unknown grant rejection.");
}
