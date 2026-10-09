using AgentShield.Application.Common.Results;

namespace AgentShield.Application.Agents.AuthorizeAgentAction;

/// <summary>
/// Decides whether an agent may perform a proposed tool action: authorization boundary (capability check, risk
/// classification, policy) → security event to every sink → decision. Executes nothing.
/// </summary>
/// <remarks>
/// Expects a request that passed <see cref="AuthorizeAgentActionRequestValidator"/>. Any decision, including Block, is a
/// successful result.
/// </remarks>
public interface IAuthorizeAgentActionUseCase
{
    Task<Result<AgentActionAuthorizationResponse>> ExecuteAsync(AuthorizeAgentActionRequest request, CancellationToken cancellationToken);
}
