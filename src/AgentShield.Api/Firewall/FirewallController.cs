using System.Net.Mime;
using AgentShield.Api.Auth;
using AgentShield.Api.Http;
using AgentShield.Api.Http.Responses;
using AgentShield.Api.Http.Results;
using AgentShield.Api.RateLimiting;
using AgentShield.Application.Firewall.AnalyzeInput;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace AgentShield.Api.Firewall;

/// <summary>Firewall analysis of untrusted input bound for an AI model or agent.</summary>
/// <remarks>
/// Access and throughput are declared, not implemented, here: the named authorization and rate-limit policies are
/// defined in <c>AuthSetup</c> and <c>RateLimitingSetup</c>.
/// </remarks>
[Route(ApiRoutes.V1 + "/firewall")]
[Authorize(Policy = AuthorizationPolicies.FirewallAnalyze)]
[EnableRateLimiting(RateLimitPolicies.Firewall)]
public sealed class FirewallController(IAnalyzeInputUseCase analyzeInput) : ApiControllerBase
{
    /// <summary>Analyses untrusted input and returns a security decision.</summary>
    /// <remarks>
    /// The input is normalised, checked by every deterministic detector, scored and decided by policy; the analysis is
    /// recorded as a security event. The decision (<c>Allow</c>, <c>Review</c> or <c>Block</c>) is in the body:
    /// a successful analysis answers 200 whatever it decided.
    /// </remarks>
    /// <response code="200">The analysis completed; <c>data.decision</c> says what to do with the input.</response>
    /// <response code="400">The body is not valid JSON or does not match the contract (e.g. unknown or duplicate properties).</response>
    /// <response code="401">No valid API key (missing, malformed or unknown); the response does not say which.</response>
    /// <response code="403">The client is authenticated but lacks the <c>firewall:analyze</c> permission.</response>
    /// <response code="422">The input is missing, empty or longer than 32,000 characters.</response>
    /// <response code="429">The client exceeded the firewall rate limit; retry after <c>Retry-After</c> seconds.</response>
    /// <response code="500">The analysis failed unexpectedly; no decision was made.</response>
    [HttpPost("analyze")]
    [Consumes(MediaTypeNames.Application.Json)]
    [ProducesResponseType<ApiResponse<AnalysisResponse>>(StatusCodes.Status200OK, MediaTypeNames.Application.Json)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ValidationProblemDetails>(StatusCodes.Status422UnprocessableEntity, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status429TooManyRequests, MediaTypeNames.Application.ProblemJson)]
    public async Task<IActionResult> Analyze([FromBody] AnalyzeInputRequest request, CancellationToken cancellationToken) =>
        (await analyzeInput.ExecuteAsync(request, cancellationToken)).ToOkResult();
}
