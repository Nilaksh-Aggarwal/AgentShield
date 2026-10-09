namespace AgentShield.AI;

/// <summary>
/// AI-assisted analysis settings (section <c>Ai</c>). Validated at startup; see docs/security/ai-analysis.md, section 15.
/// </summary>
/// <remarks>
/// Committed appsettings files carry only an empty <c>Ai:Gemini:ApiKey</c> placeholder (tested). The real key comes from
/// User Secrets in Development or the <c>Ai__Gemini__ApiKey</c> environment variable elsewhere; both are added after the
/// appsettings files, so the placeholder never overrides them.
/// </remarks>
public sealed class AiOptions
{
    public const string SectionName = "Ai";

    /// <summary>The only provider implemented so far.</summary>
    public const string GeminiProvider = "Gemini";

    /// <summary>Configuration key of the Gemini API key (User Secrets / environment variable only).</summary>
    public const string GeminiApiKeyConfigurationKey = "Ai:Gemini:ApiKey";

    /// <summary>
    /// Upper bound for <see cref="TimeoutSeconds"/>: the AI analysis stage's own hard timeout (3 s,
    /// <c>AiAnalysisLimits.Timeout</c> in the Security layer), which always applies on top of the provider's.
    /// Configuration can make the provider give up sooner, never let the analysis wait longer.
    /// </summary>
    public const int MaxTimeoutSeconds = 3;

    /// <summary>Longest accepted model identifier.</summary>
    public const int MaxModelLength = 100;

    /// <summary>
    /// When off (the default), no provider is registered, no key is needed and no request leaves the process: every
    /// decision is the deterministic pipeline's.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>Which provider adapter to use. Only <see cref="GeminiProvider"/> exists.</summary>
    public string Provider { get; set; } = GeminiProvider;

    /// <summary>
    /// Model identifier sent to the provider and recorded in the audit log. Lower-case letters, digits, '.' and '-'
    /// only, because it becomes part of the request URL.
    /// </summary>
    public string Model { get; set; } = "gemini-3.8-flash";

    /// <summary>The provider call's own timeout (1 to <see cref="MaxTimeoutSeconds"/>).</summary>
    public int TimeoutSeconds { get; set; } = MaxTimeoutSeconds;

    /// <summary>Gemini-specific settings (section <c>Ai:Gemini</c>).</summary>
    public GeminiOptions Gemini { get; set; } = new();

    /// <summary>Whether <paramref name="model"/> is a well-formed model identifier.</summary>
    public static bool IsValidModel(string? model) =>
        model is { Length: > 0 and <= MaxModelLength }
        && char.IsAsciiLetterOrDigit(model[0])
        && model.All(character => char.IsAsciiLetterLower(character) || char.IsAsciiDigit(character) || character is '.' or '-');
}

/// <summary>Gemini provider settings (section <c>Ai:Gemini</c>).</summary>
public sealed class GeminiOptions
{
    /// <summary>
    /// The Gemini API key. A secret: set it with User Secrets (<c>Ai:Gemini:ApiKey</c>) or the <c>Ai__Gemini__ApiKey</c>
    /// environment variable, never in a committed file. Never log, return or serialise it. Required only when AI is
    /// enabled.
    /// </summary>
    public string? ApiKey { get; set; }

    /// <summary>Never reveals the key (defence in depth if an instance is ever formatted into a log or message).</summary>
    public override string ToString() =>
        $"{nameof(GeminiOptions)} {{ ApiKeyConfigured = {!string.IsNullOrWhiteSpace(ApiKey)} }}";
}
