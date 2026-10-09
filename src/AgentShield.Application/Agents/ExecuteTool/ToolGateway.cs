using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.Context;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Application.Common.Events;
using AgentShield.Application.Common.Results;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Domain.Policy;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Agents.ExecuteTool;

/// <summary>
/// The tool gateway's orchestration. Owns no security rule itself: the firewall's record decides what the input was, the
/// authorization boundary decides the action, a person decides a held action, the argument policy judges the arguments, and
/// the execution authority issues, verifies and consumes the grant and runs the tool. This use case puts them in order,
/// records every stage, and returns the outcome.
/// </summary>
/// <remarks>
/// <para>It never holds a tool: it cannot run one except by presenting a grant to the execution authority, and it gets a
/// grant only for an action the boundary allows, or holds for review and a person approved (the authority checks both
/// itself).</para>
/// <para>Every stage it can stop at only makes the result stricter: an input event it cannot verify blocks the call; a Block
/// is returned as decided; a Review stays held unless the request presents an approval of exactly this call; an action
/// without an executable tool, or with arguments the policy rejects, is a Block.</para>
/// </remarks>
internal sealed class ToolGateway(
    ICallerContext callerContext,
    ICorrelationContext correlationContext,
    IAgentDirectory directory,
    IAgentActionAuthorizer authorizer,
    IEnumerable<IToolArgumentPolicy> argumentPolicies,
    IToolExecutionAuthority executionAuthority,
    IInputSecurityContextStore inputContexts,
    IToolApprovalStore approvals,
    IEnumerable<IToolGatewayEventSink> eventSinks,
    TimeProvider timeProvider) : IToolGateway, IScopedService
{
    public async Task<Result<ToolExecutionResponse>> ExecuteAsync(ExecuteToolRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // The caller comes from authentication and the agent from the caller, never from the body. The value objects re-check
        // every format, so an unvalidated request fails here instead of reaching the boundary.
        var caller = callerContext.ClientId;
        var agent = AgentOf(caller);
        var tool = new ToolId(request.Tool ?? throw Unvalidated(request));
        var action = new ActionName(request.Action ?? throw Unvalidated(request));
        var capability = new Capability(request.Capability ?? throw Unvalidated(request));
        var arguments = request.Arguments is { ValueKind: JsonValueKind.Object } json ? json : throw Unvalidated(request);
        var correlationId = correlationContext.CorrelationId;
        var started = timeProvider.GetTimestamp();

        // 0. The input behind the call: the server's record of its analysis, never the caller's word. A referenced event is
        // always verified; a presented approval adds the input decision its call was held under. Each can only tighten.
        var referenced = request.InputEventId is { } eventId ? Verify(eventId, caller, correlationId) : null;
        var presented = request.ApprovalId is { } presentedId ? approvals.Find(presentedId) : null;
        var inputDecision = Strictest(Strictest(referenced?.Decision, presented?.InputDecision), request.InputDecision);
        var inputEventId = referenced?.EventId ?? presented?.Binding.InputEventId;

        var proposal = new AgentActionRequest(caller, agent, tool, action, capability, inputDecision);
        var entry = ToolGatewayEvent.Requested(SecurityEventId.New(), correlationId, timeProvider.GetUtcNow(), agent, inputDecision, inputEventId);
        await PublishAsync(entry, cancellationToken);

        // 1. The authorization boundary (M10): capability, risk, policy, with the verified input decision.
        var authorization = authorizer.Authorize(proposal);
        if (referenced?.Rejection is { } inputRejection)
        {
            return await RefuseAsync(entry, started, authorization, ToolExecutionOutcome.InputContextRejected, inputContextRejection: inputRejection, cancellationToken: cancellationToken);
        }

        if (authorization.Decision == SecurityDecision.Block)
        {
            return await RefuseAsync(entry, started, authorization, ToolExecutionOutcome.Denied, cancellationToken: cancellationToken);
        }

        // 2. A held action runs only with a person's approval of exactly this call, used once; without one, it stays held and
        // (when the gateway could run it) a pending approval is created for a person to decide.
        Guid? usedApproval = null;
        if (authorization.Decision == SecurityDecision.Review)
        {
            // The call as this request presents it; for a new approval, its input event is the one just verified.
            var binding = new ToolApprovalBinding(agent, caller, tool, action, capability, DigestOf(arguments), referenced?.EventId);
            if (request.ApprovalId is { } approvalId)
            {
                var use = approvals.TryUse(approvalId, binding, entry.Id, timeProvider.GetUtcNow());
                if (use.Rejection is { } approvalRejection)
                {
                    return await RefuseAsync(entry, started, authorization, ToolExecutionOutcome.ApprovalRejected, approvalId: approvalId, approvalRejection: approvalRejection, cancellationToken: cancellationToken);
                }

                usedApproval = approvalId;
            }
            else
            {
                return await HoldAsync(entry, started, authorization, binding, inputDecision, cancellationToken);
            }
        }

        // 3. An executable tool: the boundary can allow catalogued actions that no tool here implements.
        if (PolicyFor(tool, action) is not { } policy)
        {
            return await RefuseAsync(entry, started, authorization, ToolExecutionOutcome.ToolUnavailable, approvalId: usedApproval, cancellationToken: cancellationToken);
        }

        // 4. The action's argument policy: the tool only ever receives what it accepts.
        var check = policy.Check(arguments);
        if (check.Arguments is not { } accepted)
        {
            return await RefuseAsync(entry, started, authorization, ToolExecutionOutcome.ArgumentsRejected, check.Violation, usedApproval, cancellationToken: cancellationToken);
        }

        // 5. The execution grant: the authority asks the boundary again, and for a Review checks the approval this request used;
        // it issues nothing else.
        var grant = executionAuthority.Issue(proposal, entry.Id, correlationId, usedApproval)
            ?? throw new InvalidOperationException("The execution authority refused a grant for an action the gateway authorised.");

        entry = entry.Allowed(timeProvider.GetUtcNow(), timeProvider.GetElapsedTime(started), authorization, grant.ExecutionId, usedApproval);
        await PublishAsync(entry, cancellationToken);
        entry = entry.Started(timeProvider.GetUtcNow(), timeProvider.GetElapsedTime(started));
        await PublishAsync(entry, cancellationToken);

        // 6. The execution authority verifies and consumes the grant for what this request asks, then runs the tool once.
        // The scope comes from the gateway's own facts, not from the grant, so a grant for anything else is refused.
        var call = new ToolCall(new ExecutionScope(entry.Id, correlationId, agent, tool, action, capability), accepted);
        ToolExecutionAttempt attempt;
        try
        {
            attempt = await executionAuthority.ExecuteAsync(grant, call, cancellationToken);
        }
        catch (Exception toolFailure)
        {
            // The grant is consumed and the tool may have run, so the request's last entry is written whatever ended it,
            // a cancellation included (D-21) — with a token of its own, because the request's may be the one cancelled.
            await RecordFailureAsync(entry.Failed(timeProvider.GetUtcNow(), timeProvider.GetElapsedTime(started)), toolFailure);
            throw;
        }

        // From here the grant is consumed (and the tool may have run): the last entry is recorded with a token of its own, so a
        // request cancelled now can never leave an execution without its terminal entry.
        if (attempt.Output is not { } output)
        {
            entry = entry.GrantRefused(timeProvider.GetUtcNow(), timeProvider.GetElapsedTime(started), attempt.Rejection!.Value);
            await PublishAsync(entry, CancellationToken.None);
            return Respond(entry, output: null);
        }

        entry = entry.Completed(timeProvider.GetUtcNow(), timeProvider.GetElapsedTime(started));
        await PublishAsync(entry, CancellationToken.None);
        return Respond(entry, output);
    }

    private static ArgumentException Unvalidated(ExecuteToolRequest request) =>
        new("The request must be validated before it reaches the tool gateway.", nameof(request));

    private static ToolExecutionResponse Respond(ToolGatewayEvent terminal, ToolOutput? output)
    {
        var outcome = terminal.Outcome!.Value;
        var authorization = terminal.Authorization!;
        return new ToolExecutionResponse(
            terminal.Id.Value,
            ToolExecutionOutcomes.DecisionFor(outcome),
            Executed: output is not null,
            outcome,
            authorization.Reason,
            authorization.Risk,
            terminal.ExecutionId,
            output is null ? null : new ToolResultResponse(output.Found, output.Text),
            terminal.ApprovalId);
    }

    /// <summary>The stricter of two input decisions (Block over Review over Allow); <see langword="null"/> when neither is known.</summary>
    private static SecurityDecision? Strictest(SecurityDecision? first, SecurityDecision? second) =>
        (first, second) switch
        {
            (null, var only) => only,
            (var only, null) => only,
            ({ } a, { } b) => Rank(a) >= Rank(b) ? a : b,
        };

    private static int Rank(SecurityDecision decision) => decision switch
    {
        SecurityDecision.Allow => 0,
        SecurityDecision.Review => 1,
        _ => 2,
    };

    /// <summary>
    /// SHA-256 of the arguments exactly as sent: an approval binds the call byte for byte, without keeping the arguments.
    /// </summary>
    private static string DigestOf(JsonElement arguments) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(arguments.GetRawText())));

    /// <summary>
    /// The referenced analysis, only if the server holds it, this client made it, in this trace, and recently. Anything less
    /// is a rejection, never a fallback to the caller's report.
    /// </summary>
    private InputCheck Verify(Guid eventId, string caller, string correlationId)
    {
        var id = SecurityEventId.From(eventId);
        var context = inputContexts.Find(id);
        InputContextRejection? rejection = context switch
        {
            null => InputContextRejection.NotFound,
            _ when !string.Equals(context.Client, caller, StringComparison.Ordinal) => InputContextRejection.OtherClient,
            _ when !string.Equals(context.CorrelationId, correlationId, StringComparison.Ordinal) => InputContextRejection.OtherTrace,
            _ when timeProvider.GetUtcNow() >= context.ExpiresAt => InputContextRejection.Expired,
            _ => null,
        };

        return rejection is null ? new InputCheck(context!.Decision, id, null) : new InputCheck(null, id, rejection);
    }

    /// <summary>
    /// The agent whose gateway identity <paramref name="caller"/> is. Startup validation makes every client that may call the
    /// gateway exactly one agent's identity, so there is always one; a lookup that answers for another caller is not trusted.
    /// </summary>
    private AgentId AgentOf(string caller) =>
        directory.FindByGatewayClient(caller) is { } profile && string.Equals(profile.GatewayClient, caller, StringComparison.Ordinal)
            ? profile.Id
            : throw new InvalidOperationException("The authenticated client is not the gateway identity of a configured agent.");

    private IToolArgumentPolicy? PolicyFor(ToolId tool, ActionName action) =>
        argumentPolicies.Where(policy => policy.Tool == tool && policy.Action == action).ToArray() switch
        {
            [] => null,
            [var single] => single,
            _ => throw new InvalidOperationException("Several argument policies are registered for one tool action."),
        };

    /// <summary>
    /// The call stays held. When the gateway could run it, a pending approval is created for a person to decide: recorded in
    /// the Reviewed entry first, then stored, and withdrawn again if the request's last entry cannot be recorded, so an approval
    /// exists only when the audit log holds the request that created it.
    /// </summary>
    private async Task<Result<ToolExecutionResponse>> HoldAsync(
        ToolGatewayEvent requested,
        long started,
        AgentActionAuthorization authorization,
        ToolApprovalBinding binding,
        SecurityDecision? inputDecision,
        CancellationToken cancellationToken)
    {
        var approval = PolicyFor(binding.Tool, binding.Action) is null
            ? null
            : ToolApproval.Request(requested.Id, requested.CorrelationId, binding, authorization, inputDecision, timeProvider.GetUtcNow(), approvals.Lifetime);

        var reviewed = requested.Refused(timeProvider.GetUtcNow(), timeProvider.GetElapsedTime(started), authorization, ToolExecutionOutcome.HeldForReview, approvalId: approval?.Id);
        await PublishAsync(reviewed, cancellationToken);

        if (approval is not null)
        {
            approvals.Add(approval);
        }

        var rejected = reviewed.Rejected(timeProvider.GetUtcNow(), timeProvider.GetElapsedTime(started));
        try
        {
            await PublishAsync(rejected, cancellationToken);
        }
        catch
        {
            if (approval is not null)
            {
                approvals.Revoke(approval.Id, timeProvider.GetUtcNow());
            }

            throw;
        }

        return Respond(rejected, output: null);
    }

    private async Task<Result<ToolExecutionResponse>> RefuseAsync(
        ToolGatewayEvent requested,
        long started,
        AgentActionAuthorization authorization,
        ToolExecutionOutcome outcome,
        ToolArgumentViolation? violation = null,
        Guid? approvalId = null,
        InputContextRejection? inputContextRejection = null,
        ToolApprovalRejection? approvalRejection = null,
        CancellationToken cancellationToken = default)
    {
        var refused = requested.Refused(timeProvider.GetUtcNow(), timeProvider.GetElapsedTime(started), authorization, outcome, violation, approvalId, inputContextRejection, approvalRejection);
        await PublishAsync(refused, cancellationToken);

        var rejected = refused.Rejected(timeProvider.GetUtcNow(), timeProvider.GetElapsedTime(started));
        await PublishAsync(rejected, cancellationToken);
        return Respond(rejected, output: null);
    }

    /// <summary>Records a failed execution with a token of its own; if that fails too, both failures are raised.</summary>
    private async Task RecordFailureAsync(ToolGatewayEvent failed, Exception toolFailure)
    {
        try
        {
            await PublishAsync(failed, CancellationToken.None);
        }
        catch (Exception recordingFailure) when (recordingFailure is not OperationCanceledException)
        {
            throw new AggregateException("The tool failed, and recording its failure failed as well.", toolFailure, recordingFailure);
        }
    }

    /// <summary>
    /// Gives one entry to every sink (audit log, activity history). Every sink is tried even when one fails or is cancelled; a
    /// failure is then raised, not swallowed, so the gateway goes no further than what was recorded (the same contract as the
    /// firewall analysis and the authorization boundary).
    /// </summary>
    private Task PublishAsync(ToolGatewayEvent toolGatewayEvent, CancellationToken cancellationToken) =>
        EventSinks.PublishToEveryAsync(eventSinks, toolGatewayEvent, static (sink, entry, token) => sink.PublishAsync(entry, token), "Tool gateway event sinks failed to record the event.", cancellationToken);

    /// <summary>What the gateway knows about the input behind a call: its decision, its event, or why the event was rejected.</summary>
    private sealed record InputCheck(SecurityDecision? Decision, SecurityEventId? EventId, InputContextRejection? Rejection);
}
