using System.Net.Mime;
using AgentShield.Api.RateLimiting;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace AgentShield.Api.Http;

/// <summary>
/// Base class for every API controller: automatic 400 for malformed bodies and the Problem Details
/// responses every endpoint can produce.
/// </summary>
/// <remarks>
/// <para>Controllers stay thin: bind → call one Application use case → map the <c>Result</c> with
/// <c>ResultActionResultExtensions</c>. No business rules, data access, AI calls or security logic here.
/// Routes use <see cref="ApiRoutes"/>, e.g. <c>[Route(ApiRoutes.V1 + "/firewall")]</c>.</para>
/// <para>Do not add <c>[Produces]</c> at controller level: it is a result filter that rewrites the
/// content type of every <see cref="ObjectResult"/>, turning <c>application/problem+json</c> error
/// responses into <c>application/json</c>. Document responses with <c>[ProducesResponseType]</c>.</para>
/// <para>Every controller gets the <see cref="RateLimitPolicies.Standard"/> rate limit; a controller or action declares
/// its own <c>[EnableRateLimiting]</c> to replace it (the attribute is inherited and single, so the most derived wins;
/// an endpoint convention on <c>MapControllers</c> would instead override every attribute). Authorization needs no
/// declaration: the fallback policy requires an authenticated client unless an endpoint says otherwise.</para>
/// </remarks>
[ApiController]
[EnableRateLimiting(RateLimitPolicies.Standard)]
[ProducesResponseType<ProblemDetails>(StatusCodes.Status500InternalServerError, MediaTypeNames.Application.ProblemJson)]
public abstract class ApiControllerBase : ControllerBase;
