using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.Context;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Common.Events;
using AgentShield.Application.Common.Results;
using AgentShield.Domain.Agents;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Agents.AuthorizeAgentAction;

/// <summary>
/// Orchestrates one authorization decision. Owns no rule itself: the authorization boundary (Security layer) decides, and
/// this use case records that decision and returns it unchanged.
/// </summary>
internal sealed class AuthorizeAgentActionUseCase(
    IAgentActionAuthorizer authorizer,
    IEnumerable<IAgentActionEventSink> eventSinks,
    ICallerContext callerContext,
    ICorrelationContext correlationContext,
    TimeProvider timeProvider) : IAuthorizeAgentActionUseCase, IScopedService
{
    public async Task<Result<AgentActionAuthorizationResponse>> ExecuteAsync(AuthorizeAgentActionRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        // The value objects re-check every format, so an unvalidated request fails here instead of reaching the boundary.
        // The caller comes from authentication, never from the body.
        var proposal = new AgentActionRequest(
            callerContext.ClientId,
            new AgentId(request.AgentId ?? throw Unvalidated(request)),
            new ToolId(request.Tool ?? throw Unvalidated(request)),
            new ActionName(request.Action ?? throw Unvalidated(request)),
            new Capability(request.Capability ?? throw Unvalidated(request)),
            request.InputDecision);

        var started = timeProvider.GetTimestamp();
        var authorization = authorizer.Authorize(proposal);

        var agentActionEvent = new AgentActionEvent(
            SecurityEventId.New(),
            correlationContext.CorrelationId,
            timeProvider.GetUtcNow(),
            authorization,
            proposal.InputDecision,
            timeProvider.GetElapsedTime(started));

        await PublishAsync(agentActionEvent, cancellationToken);

        return new AgentActionAuthorizationResponse(
            agentActionEvent.Id.Value,
            authorization.Decision,
            authorization.Risk,
            authorization.Reason);
    }

    private static ArgumentException Unvalidated(AuthorizeAgentActionRequest request) =>
        new("The request must be validated before authorization.", nameof(request));

    /// <summary>
    /// Gives the finished event to every sink (audit log, activity history) after the decision was made, so none can change
    /// it. Every sink is tried even when one fails or is cancelled; a failure is then raised, not swallowed, so no decision is
    /// returned that was not recorded (the same contract as the firewall analysis).
    /// </summary>
    private Task PublishAsync(AgentActionEvent agentActionEvent, CancellationToken cancellationToken)
        => EventSinks.PublishToEveryAsync(eventSinks, agentActionEvent, static (sink, entry, token) => sink.PublishAsync(entry, token), "Agent action event sinks failed to record the event.", cancellationToken);
}
