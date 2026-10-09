using System.Net.Mime;
using AgentShield.Api.Auth;
using AgentShield.Api.Http;
using AgentShield.Api.Http.Responses;
using AgentShield.Api.Http.Results;
using AgentShield.Application.Agents.ExecuteTool;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AgentShield.Api.Agents;

/// <summary>The tool gateway: executes a tool action for the calling agent if, and only if, AgentShield allows it.</summary>
/// <remarks>
/// For an agent's own credential (<c>tool:execute</c>): the client is the gateway identity of exactly one agent, and the
/// gateway acts as that agent only. Rate limited by the <c>Standard</c> policy inherited from <see cref="ApiControllerBase"/>:
/// the reference tool is an in-memory lookup (no AI call, no I/O).
/// </remarks>
[Route(ApiRoutes.V1 + "/agent/tools")]
[Authorize(Policy = AuthorizationPolicies.ToolExecute)]
public sealed class AgentToolsController(IToolGateway toolGateway) : ApiControllerBase
{
    /// <summary>Executes a tool action through the tool gateway. The tool runs only on Allow.</summary>
    /// <remarks>
    /// The agent is the one the API key identifies, never a body field. The authorization boundary decides first
    /// (configured agent, catalogued action, exactly the required capability, held by the agent; Low or Medium risk → Allow,
    /// High → Review, Critical → Block); an optional <c>inputDecision</c> can only make that stricter. On Allow the action's
    /// argument policy must accept <c>arguments</c>, then a signed, single-use execution grant is issued, verified and
    /// consumed, and the tool runs once. Review, Block, any 4xx and any 5xx mean the tool did not run, except a 500 after
    /// the tool started (recorded as a failed execution). Every decision is a 200 with the decision in the body, and every
    /// stage is recorded as a security event. The one executable tool is <c>knowledge.lookup</c>
    /// (capability <c>knowledge:read</c>, arguments <c>{ "query": "1-200 characters" }</c>).
    /// </remarks>
    /// <response code="200">The request was decided; <c>data.executed</c> says whether the tool ran, <c>data.result</c> holds its result.</response>
    /// <response code="400">The body is not valid JSON or does not match the contract (e.g. an agent ID, a decision, grants, an execution authorization or a credential).</response>
    /// <response code="401">No valid API key (missing, malformed or unknown); the response does not say which.</response>
    /// <response code="403">The client is authenticated but lacks the <c>tool:execute</c> permission.</response>
    /// <response code="422">A field is missing or not an exact name, or <c>arguments</c> is not a JSON object.</response>
    /// <response code="429">The client exceeded its rate limit; retry after <c>Retry-After</c> seconds.</response>
    /// <response code="500">The request could not be decided, recorded or completed; no decision or result was returned.</response>
    [HttpPost("execute")]
    [Consumes(MediaTypeNames.Application.Json)]
    [ProducesResponseType<ApiResponse<ToolExecutionResponse>>(StatusCodes.Status200OK, MediaTypeNames.Application.Json)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ValidationProblemDetails>(StatusCodes.Status422UnprocessableEntity, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status429TooManyRequests, MediaTypeNames.Application.ProblemJson)]
    public async Task<IActionResult> Execute([FromBody] ExecuteToolRequest request, CancellationToken cancellationToken) =>
        (await toolGateway.ExecuteAsync(request, cancellationToken)).ToOkResult();
}
