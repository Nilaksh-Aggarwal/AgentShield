using AgentShield.Application.Abstractions.Context;

namespace AgentShield.Api.Correlation;

/// <summary>
/// Exposes the current request's correlation ID (set by <see cref="CorrelationIdMiddleware"/>) to use cases.
/// </summary>
internal sealed class HttpCorrelationContext(IHttpContextAccessor httpContextAccessor) : ICorrelationContext
{
    public string CorrelationId => httpContextAccessor.HttpContext?.GetCorrelationId()
        ?? throw new InvalidOperationException("No HTTP request is in progress, so there is no correlation ID.");
}
