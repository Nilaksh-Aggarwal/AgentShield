using System.Buffers;
using Microsoft.Extensions.Options;

namespace AgentShield.Api.Auth;

/// <summary>
/// API clients allowed to call the API (section <c>Authentication</c>), keyed by client ID:
/// <c>Authentication:Clients:{clientId}:KeyHashes</c> and <c>...:Permissions</c>. Validated at startup.
/// </summary>
/// <remarks>
/// Only key hashes are configured (<see cref="ApiKeys"/>). Several hashes per client allow key rotation without
/// downtime. Production clients come from environment variables or a secret store, like any other deployment secret;
/// the committed appsettings.json configures none.
/// </remarks>
public sealed class ApiAuthenticationOptions
{
    public const string SectionName = "Authentication";

    public IDictionary<string, ApiClientOptions> Clients { get; } = new Dictionary<string, ApiClientOptions>(StringComparer.Ordinal);
}

/// <summary>One API client (section <c>Authentication:Clients:{clientId}</c>).</summary>
public sealed class ApiClientOptions
{
    /// <summary>SHA-256 hashes (64 hex characters) of the client's valid keys.</summary>
    public IList<string> KeyHashes { get; } = [];

    /// <summary>Permissions granted to the client (<see cref="Auth.Permissions"/>). Empty: authenticated, allowed nothing.</summary>
    public IList<string> Permissions { get; } = [];
}

/// <summary>Startup validation of <see cref="ApiAuthenticationOptions"/>. Messages name clients, never hashes.</summary>
internal sealed class ApiAuthenticationOptionsValidator(IHostEnvironment environment) : IValidateOptions<ApiAuthenticationOptions>
{
    /// <summary>Client IDs appear in logs and claims: short, lower-case, no separators an attacker could exploit.</summary>
    public const int MaxClientIdLength = 64;

    private static readonly SearchValues<char> ClientIdCharacters =
        SearchValues.Create("abcdefghijklmnopqrstuvwxyz0123456789-._");

    public ValidateOptionsResult Validate(string? name, ApiAuthenticationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var failures = new List<string>();
        var seenHashes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (clientId, client) in options.Clients)
        {
            if (clientId is not { Length: > 0 and <= MaxClientIdLength } || clientId.AsSpan().ContainsAnyExcept(ClientIdCharacters))
            {
                failures.Add($"Authentication:Clients: a client ID must be 1-{MaxClientIdLength} characters of lower-case letters, digits, '-', '.' and '_'.");
                continue;
            }

            if (client.KeyHashes.Count == 0)
            {
                failures.Add($"Authentication:Clients:{clientId} has no KeyHashes.");
            }

            foreach (var hash in client.KeyHashes)
            {
                if (ApiKeys.ParseHash(hash) is null)
                {
                    failures.Add($"Authentication:Clients:{clientId}:KeyHashes contains a value that is not a SHA-256 hash (64 hex characters).");
                }
                else if (!seenHashes.Add(hash))
                {
                    failures.Add($"Authentication:Clients:{clientId}:KeyHashes repeats a key hash already configured (a key must identify one client).");
                }
                else if (!environment.IsDevelopment() && string.Equals(hash, ApiKeys.DevelopmentKeyHash, StringComparison.OrdinalIgnoreCase))
                {
                    failures.Add($"Authentication:Clients:{clientId} uses the public Development key outside the Development environment.");
                }
            }

            foreach (var permission in client.Permissions)
            {
                if (!Permissions.All.Contains(permission))
                {
                    failures.Add($"Authentication:Clients:{clientId}:Permissions contains an unknown permission.");
                }
            }

            // Separation of duties: the console that approves held calls is never an agent's credential, so no agent can
            // approve its own calls. Development's single public key holds every permission for the demo.
            if (!environment.IsDevelopment()
                && client.Permissions.Contains(Permissions.AgentApprove)
                && (client.Permissions.Contains(Permissions.ToolExecute) || client.Permissions.Contains(Permissions.AgentAuthorize)))
            {
                failures.Add($"Authentication:Clients:{clientId} holds agent:approve together with an agent permission (tool:execute or agent:authorize); outside Development the approver must be a separate client.");
            }
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
