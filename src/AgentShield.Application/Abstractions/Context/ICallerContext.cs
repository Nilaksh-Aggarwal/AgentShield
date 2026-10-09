namespace AgentShield.Application.Abstractions.Context;

/// <summary>
/// The authenticated caller of the operation in progress (for HTTP requests, the API client its API key identified).
/// Lets use cases and pipeline stages apply per-client rules, such as the AI capacity budget, without depending on the
/// transport.
/// </summary>
/// <remarks>
/// Exposes the client ID only: never the credential, a header or anything else the caller sent. Client IDs come from the
/// configured client set (<c>Authentication:Clients</c>), so they are bounded and safe to use as a state key or a log
/// property.
/// </remarks>
public interface ICallerContext
{
    /// <summary>The authenticated client's ID.</summary>
    /// <exception cref="InvalidOperationException">No authenticated client is in scope. Every analysis endpoint requires
    /// authentication, so this is a composition error.</exception>
    string ClientId { get; }
}
