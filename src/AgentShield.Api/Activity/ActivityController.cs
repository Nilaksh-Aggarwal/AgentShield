using System.Net.Mime;
using AgentShield.Api.Auth;
using AgentShield.Api.Http;
using AgentShield.Api.Http.Responses;
using AgentShield.Api.Http.Results;
using AgentShield.Application.Activity.ListActivity;
using AgentShield.Application.Activity.SummariseActivity;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AgentShield.Api.Activity;

/// <summary>The security activity history: what AgentShield decided recently, as metadata only.</summary>
/// <remarks>
/// Read-only and operator-only (<c>activity:read</c>, which firewall clients do not need). Rate limited by the
/// <c>Standard</c> policy inherited from <see cref="ApiControllerBase"/>.
/// </remarks>
[Route(ApiRoutes.V1 + "/activity")]
[Authorize(Policy = AuthorizationPolicies.ActivityRead)]
public sealed class ActivityController(IListActivityUseCase listActivity, IActivitySummaryUseCase summariseActivity) : ApiControllerBase
{
    /// <summary>Counts the events the history holds right now, by decision and kind.</summary>
    /// <remarks>
    /// Counts only, all from one snapshot of the in-memory history (the most recent events of this API process, every client
    /// together, emptied on restart): not a measure over a period and not the audit trail. <c>toolsExecuted</c> counts tool
    /// calls whose tool ran and returned a result.
    /// </remarks>
    /// <response code="200">The counts; all zero when the history is empty.</response>
    /// <response code="401">No valid API key (missing, malformed or unknown); the response does not say which.</response>
    /// <response code="403">The client is authenticated but lacks the <c>activity:read</c> permission.</response>
    /// <response code="429">The client exceeded its rate limit; retry after <c>Retry-After</c> seconds.</response>
    [HttpGet("summary")]
    [ProducesResponseType<ApiResponse<ActivitySummaryResponse>>(StatusCodes.Status200OK, MediaTypeNames.Application.Json)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status429TooManyRequests, MediaTypeNames.Application.ProblemJson)]
    public async Task<IActionResult> Summary(CancellationToken cancellationToken) =>
        (await summariseActivity.ExecuteAsync(cancellationToken)).ToOkResult();

    /// <summary>Lists recent security events, newest first.</summary>
    /// <remarks>
    /// Each item holds the decision, risk, finding codes, what AI-assisted analysis contributed (without a failure reason),
    /// the security event and correlation IDs and the time. Never the input, decoded content, rule IDs or provider output.
    /// The history is held in server memory: bounded to the most recent events and emptied when the server restarts.
    /// Repeat <c>decision</c> to include several decisions. A page after the last one is empty.
    /// </remarks>
    /// <response code="200">A page of the history; <c>data.items</c> may be empty.</response>
    /// <response code="400">A query value has the wrong type (e.g. <c>page=abc</c>).</response>
    /// <response code="401">No valid API key (missing, malformed or unknown); the response does not say which.</response>
    /// <response code="403">The client is authenticated but lacks the <c>activity:read</c> permission.</response>
    /// <response code="422">A page or page size out of range (page size 1–100), or a decision or risk level that is not an exact name.</response>
    /// <response code="429">The client exceeded its rate limit; retry after <c>Retry-After</c> seconds.</response>
    [HttpGet]
    [ProducesResponseType<ApiResponse<ActivityPageResponse>>(StatusCodes.Status200OK, MediaTypeNames.Application.Json)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ValidationProblemDetails>(StatusCodes.Status422UnprocessableEntity, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status429TooManyRequests, MediaTypeNames.Application.ProblemJson)]
    public async Task<IActionResult> List([FromQuery] ListActivityRequest request, CancellationToken cancellationToken) =>
        (await listActivity.ExecuteAsync(request, cancellationToken)).ToOkResult();
}
