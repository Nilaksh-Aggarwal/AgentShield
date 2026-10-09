using System.Text.RegularExpressions;

namespace AgentShield.Security.Redaction;

/// <summary>
/// Deterministic redaction of secrets before data leaves the process through logs (and, later,
/// security events). Framework-independent so any sink/adapter can reuse it.
/// </summary>
/// <remarks>
/// This is defence in depth, not permission to log sensitive data: code must still avoid logging
/// secrets, request bodies and PII in the first place.
/// </remarks>
public static partial class SensitiveDataRedactor
{
    public const string Mask = "***REDACTED***";

    // Matched as a suffix of the normalised name (lower-case, separators removed): the last word of a
    // name says what the value is. "UserPassword" / "X-Api-Key" are secrets; "PasswordPolicy",
    // "ConnectionStringName" and "PromptTokens" are not.
    private static readonly string[] SensitiveKeySuffixes =
    [
        "password", "passwords", "passwd", "passphrase", "passwordhash",
        "secret", "secrets", "apikey", "authorization",
        "connectionstring", "credential", "credentials", "privatekey",
        "cookie", "cookies", "sessionid", "token", "jwt",
    ];

    private static readonly string[] SensitiveKeyExact = ["pwd", "pin", "otp", "ssn"];

    /// <summary>
    /// Whether a property/field name denotes a secret (e.g. <c>Password</c>, <c>api_key</c>,
    /// <c>AccessToken</c>, <c>DbConnectionString</c>). Only the trailing word counts, so
    /// descriptors such as <c>ConnectionStringName</c> or LLM counters such as <c>PromptTokens</c>
    /// are not masked.
    /// </summary>
    public static bool IsSensitiveKey(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            return false;
        }

        var normalized = Normalize(name);

        return Array.Exists(SensitiveKeySuffixes, suffix => normalized.EndsWith(suffix, StringComparison.Ordinal))
            || Array.Exists(SensitiveKeyExact, exact => normalized == exact);
    }

    /// <summary>
    /// Masks secret-looking substrings inside free text: bearer tokens, JWTs, credential assignments
    /// (<c>password=...</c>) and well-known API key formats.
    /// </summary>
    public static string RedactValue(string? value) =>
        // Fail closed: if the input cannot be scanned in time, do not emit it.
        TryRedactValue(value, out var redacted) ? redacted : Mask;

    /// <summary>
    /// Like <see cref="RedactValue"/>, but tells the caller whether the value could be scanned in time, so a caller that
    /// must not act on a fully masked value (e.g. disclosure to an AI provider) can tell the two apart.
    /// </summary>
    /// <returns><see langword="false"/> if a pattern timed out; <paramref name="redacted"/> is then <see cref="Mask"/>.</returns>
    public static bool TryRedactValue(string? value, out string redacted)
    {
        if (string.IsNullOrEmpty(value))
        {
            redacted = value ?? string.Empty;
            return true;
        }

        try
        {
            var result = BearerTokenPattern().Replace(value, "Bearer " + Mask);
            result = JwtPattern().Replace(result, Mask);
            result = CredentialAssignmentPattern().Replace(result, match => $"{match.Groups["key"].Value}{match.Groups["sep"].Value}{Mask}");
            redacted = ApiKeyPattern().Replace(result, Mask);
            return true;
        }
        catch (RegexMatchTimeoutException)
        {
            redacted = Mask;
            return false;
        }
    }

    private static string Normalize(string name)
    {
        Span<char> buffer = name.Length <= 256 ? stackalloc char[name.Length] : new char[name.Length];
        var length = 0;
        foreach (var character in name)
        {
            if (char.IsLetterOrDigit(character))
            {
                buffer[length++] = char.ToLowerInvariant(character);
            }
        }

        return new string(buffer[..length]);
    }

    [GeneratedRegex(@"Bearer\s+[A-Za-z0-9\-._~+/]+=*", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 250)]
    private static partial Regex BearerTokenPattern();

    [GeneratedRegex(@"eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 250)]
    private static partial Regex JwtPattern();

    [GeneratedRegex(
        @"(?<key>\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret)\b)(?<sep>\s*[=:]\s*)(?:""[^""]*""|'[^']*'|[^\s;,&""']+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant,
        matchTimeoutMilliseconds: 250)]
    private static partial Regex CredentialAssignmentPattern();

    // sk-... (OpenAI / Anthropic style), AKIA... (AWS access key id), ghp_... (GitHub PAT), AIza... (Google API key, as
    // used by Gemini: "AIza" and 35 characters, which may end in '-', so no trailing word boundary).
    [GeneratedRegex(@"\b(?:sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{30,})\b|AIza[0-9A-Za-z_-]{35}", RegexOptions.CultureInvariant, matchTimeoutMilliseconds: 250)]
    private static partial Regex ApiKeyPattern();
}
