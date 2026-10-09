using System.Buffers;
using System.Security.Cryptography;
using System.Text;

namespace AgentShield.Api.Auth;

/// <summary>
/// API key format and hashing. Configuration stores only the SHA-256 hash of each key (lower-case hex), so neither the
/// configuration nor a memory dump holds a usable key. Keys are random and at least 32 characters long, so an unsalted
/// hash is not guessable (see docs/decisions/0014-api-boundary-hardening.md).
/// </summary>
public static class ApiKeys
{
    /// <summary>Request header carrying the key.</summary>
    public const string HeaderName = "X-API-Key";

    /// <summary>Authentication scheme name (also the <c>WWW-Authenticate</c> challenge).</summary>
    public const string Scheme = "ApiKey";

    public const int MinKeyLength = 32;

    public const int MaxKeyLength = 256;

    /// <summary>
    /// Hash of the public, Development-only key <c>agentshield-development-only-key-not-a-secret</c>
    /// (appsettings.Development.json). Startup fails if any client uses it outside Development.
    /// </summary>
    public const string DevelopmentKeyHash = "a6fe8444310e70027e4344a24208dd445e74f38c4d0ccff50aa3edffae3b59cc";

    // Base64url and the other RFC 3986 unreserved characters. No spaces, commas or control characters, so a header
    // cannot smuggle a second value or anything a log could misinterpret.
    private static readonly SearchValues<char> KeyCharacters =
        SearchValues.Create("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~");

    /// <summary>Whether <paramref name="key"/> has the shape of a key. Says nothing about whether it is valid.</summary>
    public static bool IsWellFormedKey(string? key) =>
        key is { Length: >= MinKeyLength and <= MaxKeyLength } && !key.AsSpan().ContainsAnyExcept(KeyCharacters);

    /// <summary>SHA-256 of the UTF-8 key.</summary>
    public static byte[] Hash(string key)
    {
        ArgumentNullException.ThrowIfNull(key);
        return SHA256.HashData(Encoding.UTF8.GetBytes(key));
    }

    /// <summary>Parses a configured hash (64 hex characters, any case); <see langword="null"/> if malformed.</summary>
    public static byte[]? ParseHash(string? hash)
    {
        if (hash is not { Length: SHA256.HashSizeInBytes * 2 })
        {
            return null;
        }

        try
        {
            return Convert.FromHexString(hash);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
