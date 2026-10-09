using System.Collections.Frozen;
using System.Security.Cryptography;
using AgentShield.Application.Abstractions.Context;
using Microsoft.Extensions.Options;

namespace AgentShield.Api.Auth;

/// <summary>
/// The configured API clients, with their key hashes decoded once at startup. Also the <see cref="IApiClientDirectory"/>
/// (client IDs only) for components that share a resource between clients, such as the AI capacity gate.
/// </summary>
internal sealed class ApiClientRegistry : IApiClientDirectory
{
    private readonly (byte[] KeyHash, ApiClient Client)[] _entries;

    public ApiClientRegistry(IOptions<ApiAuthenticationOptions> options)
    {
        ArgumentNullException.ThrowIfNull(options);

        _entries =
        [
            .. options.Value.Clients.SelectMany(client => client.Value.KeyHashes.Select(hash => (
                KeyHash: ApiKeys.ParseHash(hash) ?? throw new InvalidOperationException("Authentication options were not validated."),
                Client: new ApiClient(client.Key, client.Value.Permissions.ToFrozenSet(StringComparer.Ordinal))))),
        ];

        // The clients that can reach the firewall analysis, and so its AI stage: those holding its permission.
        AnalysisClientIds = _entries
            .Where(entry => entry.Client.Permissions.Contains(Permissions.FirewallAnalyze))
            .Select(entry => entry.Client.ClientId)
            .ToFrozenSet(StringComparer.Ordinal);

        // The clients that can ask the agent action authorization boundary: the only ones an agent can be bound to.
        AgentAuthorizationClientIds = _entries
            .Where(entry => entry.Client.Permissions.Contains(Permissions.AgentAuthorize))
            .Select(entry => entry.Client.ClientId)
            .ToFrozenSet(StringComparer.Ordinal);

        // The clients that can call the tool gateway: each must be exactly one agent's gateway identity (agent validation).
        ToolExecutionClientIds = _entries
            .Where(entry => entry.Client.Permissions.Contains(Permissions.ToolExecute))
            .Select(entry => entry.Client.ClientId)
            .ToFrozenSet(StringComparer.Ordinal);
    }

    public int ClientCount => _entries.Select(entry => entry.Client.ClientId).Distinct(StringComparer.Ordinal).Count();

    public IReadOnlySet<string> AnalysisClientIds { get; }

    public IReadOnlySet<string> AgentAuthorizationClientIds { get; }

    public IReadOnlySet<string> ToolExecutionClientIds { get; }

    /// <summary>
    /// The client owning <paramref name="key"/>, or <see langword="null"/>. Compares against every configured hash in
    /// constant time, whether or not an earlier one matched.
    /// </summary>
    public ApiClient? Find(string key)
    {
        var hash = ApiKeys.Hash(key);
        ApiClient? match = null;
        foreach (var (keyHash, client) in _entries)
        {
            if (CryptographicOperations.FixedTimeEquals(hash, keyHash))
            {
                match = client;
            }
        }

        return match;
    }
}

/// <summary>An authenticated API client: its ID and granted permissions.</summary>
internal sealed record ApiClient(string ClientId, IReadOnlySet<string> Permissions);
