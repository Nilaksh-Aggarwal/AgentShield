using System.Net.Mime;
using AgentShield.Api.Auth;
using AgentShield.Api.Http;
using AgentShield.Api.Http.Responses;
using AgentShield.Api.Http.Results;
using AgentShield.Application.Agents.Approvals;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AgentShield.Api.Agents;

/// <summary>
/// A person's approval of tool calls the gateway held for review (ADR 0023): list them, approve one, deny one.
/// </summary>
/// <remarks>
/// <para>Only clients holding <c>agent:approve</c> (a person's console; never an agent's credential outside Development).
/// Rate limited by the <c>Standard</c> policy inherited from <see cref="ApiControllerBase"/>.</para>
/// <para>The decision endpoints take no body: the approval, the exact call it binds, its risk and reason all come from the
/// server's own state, so nothing a client sends can change what is approved. Approving runs nothing: the agent presents
/// the approval with the same call to the tool gateway, once.</para>
/// </remarks>
[Route(ApiRoutes.V1 + "/agent/approvals")]
[Authorize(Policy = AuthorizationPolicies.AgentApprove)]
public sealed class AgentApprovalsController(IListToolApprovalsUseCase listApprovals, IDecideToolApprovalUseCase decideApproval) : ApiControllerBase
{
    /// <summary>Lists the most recent approvals (at most 50), newest first, each with its status now.</summary>
    /// <response code="200">The approvals; metadata only (never the call's arguments).</response>
    /// <response code="401">No valid API key (missing, malformed or unknown); the response does not say which.</response>
    /// <response code="403">The client is authenticated but lacks the <c>agent:approve</c> permission.</response>
    /// <response code="429">The client exceeded its rate limit; retry after <c>Retry-After</c> seconds.</response>
    [HttpGet]
    [ProducesResponseType<ApiResponse<ToolApprovalListResponse>>(StatusCodes.Status200OK, MediaTypeNames.Application.Json)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status429TooManyRequests, MediaTypeNames.Application.ProblemJson)]
    public async Task<IActionResult> List(CancellationToken cancellationToken) =>
        (await listApprovals.ExecuteAsync(cancellationToken)).ToOkResult();

    /// <summary>Approves a pending approval: the exact held call may then run once, until the approval expires.</summary>
    /// <param name="approvalId">The approval, as the tool gateway returned it for the held call.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    /// <response code="200">Approved.</response>
    /// <response code="401">No valid API key.</response>
    /// <response code="403">The client lacks the <c>agent:approve</c> permission.</response>
    /// <response code="404">No such approval is held.</response>
    /// <response code="409">Already decided or used, or expired before it was decided.</response>
    /// <response code="429">Rate limited; retry after <c>Retry-After</c> seconds.</response>
    [HttpPost("{approvalId}/approve")]
    [ProducesResponseType<ApiResponse<ToolApprovalResponse>>(StatusCodes.Status200OK, MediaTypeNames.Application.Json)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status404NotFound, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status409Conflict, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status429TooManyRequests, MediaTypeNames.Application.ProblemJson)]
    public async Task<IActionResult> Approve(Guid approvalId, CancellationToken cancellationToken) =>
        (await decideApproval.ExecuteAsync(approvalId, approve: true, cancellationToken)).ToOkResult();

    /// <summary>Denies a pending approval: the held call will not run.</summary>
    /// <param name="approvalId">The approval, as the tool gateway returned it for the held call.</param>
    /// <param name="cancellationToken">Request cancellation.</param>
    /// <response code="200">Denied.</response>
    /// <response code="401">No valid API key.</response>
    /// <response code="403">The client lacks the <c>agent:approve</c> permission.</response>
    /// <response code="404">No such approval is held.</response>
    /// <response code="409">Already decided or used, or expired before it was decided.</response>
    /// <response code="429">Rate limited; retry after <c>Retry-After</c> seconds.</response>
    [HttpPost("{approvalId}/deny")]
    [ProducesResponseType<ApiResponse<ToolApprovalResponse>>(StatusCodes.Status200OK, MediaTypeNames.Application.Json)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status404NotFound, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status409Conflict, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status429TooManyRequests, MediaTypeNames.Application.ProblemJson)]
    public async Task<IActionResult> Deny(Guid approvalId, CancellationToken cancellationToken) =>
        (await decideApproval.ExecuteAsync(approvalId, approve: false, cancellationToken)).ToOkResult();
}
