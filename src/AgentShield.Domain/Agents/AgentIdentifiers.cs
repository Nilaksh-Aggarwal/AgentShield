using System.Buffers;

namespace AgentShield.Domain.Agents;

/// <summary>
/// The one format of every name in an agent action: agent IDs, tool IDs, action names and the two halves of a capability.
/// </summary>
/// <remarks>
/// <para>A name is 1–<see cref="MaxLength"/> characters of lower-case ASCII letters, digits, <c>.</c>, <c>_</c> and
/// <c>-</c>, starting with a letter or digit. A capability is two names without dots joined by one colon
/// (<c>email:send</c>), at most <see cref="MaxLength"/> characters in all.</para>
/// <para>Names are compared exactly (ordinal), and nothing is normalised: <c>Email</c>, <c> email</c> or a Cyrillic look-alike
/// of <c>email</c> is not another spelling of <c>email</c> but an invalid name. One spelling per name means a request cannot
/// pass a check under one reading and be acted on under another.</para>
/// </remarks>
public static class AgentIdentifiers
{
    public const int MaxLength = 64;

    private static readonly SearchValues<char> NameCharacters = SearchValues.Create("abcdefghijklmnopqrstuvwxyz0123456789._-");

    private static readonly SearchValues<char> CapabilityPartCharacters = SearchValues.Create("abcdefghijklmnopqrstuvwxyz0123456789_-");

    private static readonly SearchValues<char> LeadingCharacters = SearchValues.Create("abcdefghijklmnopqrstuvwxyz0123456789");

    /// <summary>Whether <paramref name="value"/> is a valid agent ID, tool ID or action name.</summary>
    public static bool IsValidName(string? value) =>
        value is { Length: > 0 and <= MaxLength }
        && LeadingCharacters.Contains(value[0])
        && !value.AsSpan().ContainsAnyExcept(NameCharacters);

    /// <summary>Whether <paramref name="value"/> is a valid capability (<c>resource:operation</c>).</summary>
    public static bool IsValidCapability(string? value)
    {
        if (value is not { Length: > 0 and <= MaxLength })
        {
            return false;
        }

        var separator = value.IndexOf(':', StringComparison.Ordinal);
        return separator > 0
            && IsCapabilityPart(value.AsSpan(0, separator))
            && IsCapabilityPart(value.AsSpan(separator + 1));
    }

    private static bool IsCapabilityPart(ReadOnlySpan<char> part) =>
        part.Length > 0 && LeadingCharacters.Contains(part[0]) && !part.ContainsAnyExcept(CapabilityPartCharacters);
}
