using System.Net.Mime;
using AgentShield.Api.Auth;
using AgentShield.Api.Http;
using AgentShield.Api.Http.Responses;
using AgentShield.Api.Http.Results;
using AgentShield.Application.Agents.AuthorizeAgentAction;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AgentShield.Api.Agents;

/// <summary>The agent action authorization boundary: may this agent perform this tool action? Nothing is executed.</summary>
/// <remarks>
/// For the runtime that executes an agent's tool calls (<c>agent:authorize</c>). Rate limited by the <c>Standard</c> policy
/// inherited from <see cref="ApiControllerBase"/>: a decision is cheap (no AI call, no I/O beyond in-memory lookups).
/// </remarks>
[Route(ApiRoutes.V1 + "/agent/actions")]
[Authorize(Policy = AuthorizationPolicies.AgentAuthorize)]
public sealed class AgentActionsController(IAuthorizeAgentActionUseCase authorizeAgentAction) : ApiControllerBase
{
    /// <summary>Decides whether an agent may perform a tool action. Executes nothing.</summary>
    /// <remarks>
    /// The agent must be configured in AgentShield, the tool action must be in its catalogue, the capability must be exactly
    /// the one that action requires, and the agent must hold it. The action's risk then decides: Low or Medium → Allow,
    /// High → Review (a person approves first), Critical → Block. Anything unknown is blocked. An optional
    /// <c>inputDecision</c> (the firewall's decision on the input behind the action) can only make the decision stricter.
    /// Only <c>Allow</c> permits executing the action. The decision is in the body: a successful authorization answers 200
    /// whatever it decided, and is recorded as a security event.
    /// </remarks>
    /// <response code="200">The request was decided; <c>data.decision</c> says whether the action may run.</response>
    /// <response code="400">The body is not valid JSON or does not match the contract (e.g. unknown properties such as tool arguments, a decision or extra capabilities).</response>
    /// <response code="401">No valid API key (missing, malformed or unknown); the response does not say which.</response>
    /// <response code="403">The client is authenticated but lacks the <c>agent:authorize</c> permission.</response>
    /// <response code="422">A field is missing or not an exact name (lower-case ASCII; a capability is <c>resource:operation</c>).</response>
    /// <response code="429">The client exceeded its rate limit; retry after <c>Retry-After</c> seconds.</response>
    /// <response code="500">The decision could not be made or recorded; no decision was returned, so the action must not run.</response>
    [HttpPost("authorize")]
    [Consumes(MediaTypeNames.Application.Json)]
    [ProducesResponseType<ApiResponse<AgentActionAuthorizationResponse>>(StatusCodes.Status200OK, MediaTypeNames.Application.Json)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ValidationProblemDetails>(StatusCodes.Status422UnprocessableEntity, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status429TooManyRequests, MediaTypeNames.Application.ProblemJson)]
    public async Task<IActionResult> Authorize([FromBody] AuthorizeAgentActionRequest request, CancellationToken cancellationToken) =>
        (await authorizeAgentAction.ExecuteAsync(request, cancellationToken)).ToOkResult();
}
