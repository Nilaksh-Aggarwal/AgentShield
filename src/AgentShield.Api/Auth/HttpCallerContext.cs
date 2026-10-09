using System.Security.Claims;
using AgentShield.Application.Abstractions.Context;

namespace AgentShield.Api.Auth;

/// <summary>
/// Exposes the current request's authenticated client ID (the <see cref="ClaimTypes.NameIdentifier"/> claim that
/// <see cref="ApiKeyAuthenticationHandler"/> issues from the configured client set) to use cases and pipeline stages.
/// Never the key or any other header.
/// </summary>
internal sealed class HttpCallerContext(IHttpContextAccessor httpContextAccessor) : ICallerContext
{
    public string ClientId => httpContextAccessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier)
        ?? throw new InvalidOperationException("No authenticated API client is in scope.");
}
