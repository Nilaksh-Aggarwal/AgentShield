using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.Context;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Common.Events;
using AgentShield.Application.Common.Results;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Agents.Approvals;

/// <summary>A person approves or denies a held tool call.</summary>
public interface IDecideToolApprovalUseCase
{
    /// <summary>
    /// Approves (<paramref name="approve"/>) or denies the pending approval <paramref name="approvalId"/>. Nothing about the
    /// call comes from the request: the server resolves the approval from its own state, and the approval stays bound to the
    /// exact call it was created for. Approving runs nothing: the agent presents the approval with the same call, once.
    /// </summary>
    Task<Result<ToolApprovalResponse>> ExecuteAsync(Guid approvalId, bool approve, CancellationToken cancellationToken);
}

/// <summary>The most recent approvals, for the person deciding them.</summary>
public interface IListToolApprovalsUseCase
{
    Task<Result<ToolApprovalListResponse>> ExecuteAsync(CancellationToken cancellationToken);
}

/// <summary>Stable error codes of the approval endpoints. Messages never repeat what the client sent.</summary>
public static class ToolApprovalErrors
{
    public static readonly Error NotFound = Error.NotFound("Approval.NotFound", "No approval with this ID is held.");

    public static readonly Error AlreadyDecided = Error.Conflict("Approval.AlreadyDecided", "This approval was already decided or used; an approval is decided once.");

    public static readonly Error Expired = Error.Conflict("Approval.Expired", "This approval expired before it was decided; the held call will not run.");
}

internal sealed class DecideToolApprovalUseCase(
    IToolApprovalStore store,
    ICallerContext callerContext,
    ICorrelationContext correlationContext,
    IEnumerable<IToolApprovalEventSink> eventSinks,
    TimeProvider timeProvider) : IDecideToolApprovalUseCase, IScopedService
{
    public async Task<Result<ToolApprovalResponse>> ExecuteAsync(Guid approvalId, bool approve, CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();

        // The deciding client comes from authentication; the approval, its call and its risk from the store. The decision is
        // only begun here: the stored approval stays pending, so nothing can use it until the decision is recorded.
        var decision = store.TryBeginDecision(approvalId, approve, callerContext.ClientId, now);
        if (decision.Failure is { } failure)
        {
            return failure switch
            {
                ToolApprovalDecisionFailure.NotFound => ToolApprovalErrors.NotFound,
                ToolApprovalDecisionFailure.Expired => ToolApprovalErrors.Expired,
                _ => ToolApprovalErrors.AlreadyDecided,
            };
        }

        var approval = decision.Approval!;
        try
        {
            // Recorded before the decision takes effect.
            await EventSinks.PublishToEveryAsync(
                eventSinks,
                new ToolApprovalEvent(approval, correlationContext.CorrelationId, now),
                static (sink, entry, token) => sink.PublishAsync(entry, token),
                "Tool approval event sinks failed to record the decision.",
                cancellationToken);
        }
        catch
        {
            // A decision the audit log does not hold never takes effect: withdraw the approval, then fail the request.
            store.Revoke(approvalId, timeProvider.GetUtcNow());
            throw;
        }

        store.CompleteDecision(approvalId);
        return ToolApprovalResponse.From(approval, now);
    }
}

internal sealed class ListToolApprovalsUseCase(IToolApprovalStore store, TimeProvider timeProvider) : IListToolApprovalsUseCase, IScopedService
{
    /// <summary>How many approvals one listing returns at most.</summary>
    public const int MaxItems = 50;

    public Task<Result<ToolApprovalListResponse>> ExecuteAsync(CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var items = store.Recent(MaxItems).Select(approval => ToolApprovalResponse.From(approval, now)).ToArray();
        return Task.FromResult<Result<ToolApprovalListResponse>>(new ToolApprovalListResponse(items));
    }
}
