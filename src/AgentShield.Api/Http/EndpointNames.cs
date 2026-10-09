using Microsoft.AspNetCore.Diagnostics;

namespace AgentShield.Api.Http;

/// <summary>Log-safe endpoint names.</summary>
internal static class EndpointNames
{
    /// <summary>
    /// The matched route template (e.g. <c>api/v1/firewall/analyze</c>), never the raw request path, which is
    /// attacker-controlled. <c>(unmatched)</c> when no endpoint was selected.
    /// </summary>
    public static string Describe(HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        // The exception handler clears the endpoint before it handles an exception; its feature keeps the original.
        var endpoint = context.GetEndpoint() ?? context.Features.Get<IExceptionHandlerFeature>()?.Endpoint;
        return endpoint is RouteEndpoint { RoutePattern.RawText: { } template } ? template : "(unmatched)";
    }
}
