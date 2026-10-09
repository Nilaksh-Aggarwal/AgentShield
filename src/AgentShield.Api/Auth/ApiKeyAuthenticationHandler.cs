using System.Security.Claims;
using System.Text.Encodings.Web;
using AgentShield.Api.Http;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;

namespace AgentShield.Api.Auth;

/// <summary>
/// Authenticates a request by its <see cref="ApiKeys.HeaderName"/> header against <see cref="ApiClientRegistry"/>.
/// A match yields a principal with the client ID and its permission claims; authorization policies decide the rest.
/// </summary>
/// <remarks>
/// <para>Every failure (missing, malformed, repeated or unknown key) ends in the same 401: the response never says
/// which. The log records the reason category and the endpoint, never the key or the raw header.</para>
/// <para>The challenge (401) and forbid (403) responses have no body here; the status-code pages middleware turns them
/// into the standard Problem Details (<c>Auth.Unauthenticated</c> / <c>Auth.Forbidden</c>).</para>
/// </remarks>
internal sealed partial class ApiKeyAuthenticationHandler(
    IOptionsMonitor<AuthenticationSchemeOptions> options,
    ILoggerFactory loggerFactory,
    UrlEncoder encoder,
    ApiClientRegistry registry) : AuthenticationHandler<AuthenticationSchemeOptions>(options, loggerFactory, encoder)
{
    /// <summary>Failure categories (fixed vocabulary, safe to log).</summary>
    private const string MissingKey = "MissingKey";
    private const string MalformedKey = "MalformedKey";
    private const string UnknownKey = "UnknownKey";

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var values = Request.Headers[ApiKeys.HeaderName];
        if (values.Count == 0)
        {
            return Task.FromResult(AuthenticateResult.NoResult());
        }

        // Two X-API-Key headers are ambiguous: rejected rather than picking one.
        if (values.Count > 1 || !ApiKeys.IsWellFormedKey(values[0]))
        {
            return Task.FromResult(AuthenticateResult.Fail(MalformedKey));
        }

        var client = registry.Find(values[0]!);
        if (client is null)
        {
            return Task.FromResult(AuthenticateResult.Fail(UnknownKey));
        }

        Claim[] claims =
        [
            new(ClaimTypes.NameIdentifier, client.ClientId),
            new(ClaimTypes.Name, client.ClientId),
            .. client.Permissions.Order(StringComparer.Ordinal).Select(permission => new Claim(Permissions.ClaimType, permission)),
        ];
        var principal = new ClaimsPrincipal(new ClaimsIdentity(claims, Scheme.Name));
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(principal, Scheme.Name)));
    }

    protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
    {
        var result = await HandleAuthenticateOnceSafeAsync();
        var reason = result.Failure?.Message ?? MissingKey;
        LogAuthenticationFailed(Logger, reason, Request.Method, EndpointNames.Describe(Context));

        Response.StatusCode = StatusCodes.Status401Unauthorized;
        Response.Headers.WWWAuthenticate = Scheme.Name;
    }

    protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
    {
        LogAccessDenied(Logger, Context.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "(unknown)", Request.Method, EndpointNames.Describe(Context));

        Response.StatusCode = StatusCodes.Status403Forbidden;
        return Task.CompletedTask;
    }

    [LoggerMessage(EventId = 2000, Level = LogLevel.Warning, Message = "Authentication failed ({AuthFailure}) for {RequestMethod} {Endpoint}")]
    private static partial void LogAuthenticationFailed(ILogger logger, string authFailure, string requestMethod, string endpoint);

    [LoggerMessage(EventId = 2001, Level = LogLevel.Warning, Message = "Access denied to client {ClientId} for {RequestMethod} {Endpoint}")]
    private static partial void LogAccessDenied(ILogger logger, string clientId, string requestMethod, string endpoint);
}
