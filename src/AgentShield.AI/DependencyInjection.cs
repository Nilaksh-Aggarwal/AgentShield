using AgentShield.AI.Gemini;
using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Abstractions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AgentShield.AI;

public static class DependencyInjection
{
    /// <summary>
    /// Registers AI-assisted analysis adapters and their validated options (section <c>Ai</c>).
    /// </summary>
    /// <remarks>
    /// <para>Registering an <see cref="IAiSecurityAnalyzer"/> enables AI-assisted analysis; registering none leaves it
    /// disabled and the firewall decides on the deterministic pipeline alone. The provider is registered only when
    /// <c>Ai:Enabled</c> is <see langword="true"/>, so a disabled application needs no API key, makes no provider
    /// call and does not depend on the provider at startup (docs/security/ai-analysis.md, "Configuration").</para>
    /// <para>The adapter is a typed <see cref="HttpClient"/> client (transient) through <see cref="IHttpClientFactory"/>,
    /// with the configured timeout and a response size cap. No resilience handler: AI calls are never retried, and the
    /// deterministic pipeline is the fallback.</para>
    /// </remarks>
    public static IServiceCollection AddAI(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        services.AddMarkedServices(typeof(DependencyInjection).Assembly);

        // Ai:Gemini:ApiKey binds like any other value: appsettings files hold only an empty placeholder, and User Secrets
        // (Development) and environment variables are added after them, so the real key always wins.
        services.AddOptions<AiOptions>()
            .Bind(configuration.GetSection(AiOptions.SectionName))
            .Validate(
                options => string.Equals(options.Provider, AiOptions.GeminiProvider, StringComparison.Ordinal),
                $"Ai:Provider must be '{AiOptions.GeminiProvider}' (the only provider implemented).")
            .Validate(
                options => AiOptions.IsValidModel(options.Model),
                $"Ai:Model must be a model identifier of lower-case letters, digits, '.' and '-' (at most {AiOptions.MaxModelLength} characters).")
            .Validate(
                options => options.TimeoutSeconds is >= 1 and <= AiOptions.MaxTimeoutSeconds,
                $"Ai:TimeoutSeconds must be between 1 and {AiOptions.MaxTimeoutSeconds} (the AI analysis stage's hard timeout).")
            .Validate(
                options => !options.Enabled || !IsGemini(options) || !string.IsNullOrWhiteSpace(options.Gemini?.ApiKey),
                $"Ai:Enabled is true but no Gemini API key is configured: set {AiOptions.GeminiApiKeyConfigurationKey} with dotnet user-secrets (Development) or the Ai__Gemini__ApiKey environment variable.")
            .ValidateOnStart();

        if (IsEnabled(configuration))
        {
            AddGemini(services);
        }

        return services;
    }

    /// <summary>Whether <c>Ai:Enabled</c> is set to <see langword="true"/>.</summary>
    public static bool IsEnabled(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return configuration.GetSection(AiOptions.SectionName).GetValue<bool>(nameof(AiOptions.Enabled));
    }

    private static bool IsGemini(AiOptions options) =>
        string.Equals(options.Provider, AiOptions.GeminiProvider, StringComparison.Ordinal);

    private static void AddGemini(IServiceCollection services)
    {
        // Explicit (no lifetime marker): needs options and an HttpClient. Transient typed client; the scoped AI stage
        // resolves one per request and the scope disposes it.
        services.AddHttpClient<IAiSecurityAnalyzer, GeminiSecurityAnalyzer>((provider, client) =>
                GeminiSecurityAnalyzer.ConfigureHttpClient(client, provider.GetRequiredService<IOptions<AiOptions>>().Value))
            .ConfigurePrimaryHttpMessageHandler((handler, _) => GeminiSecurityAnalyzer.ConfigurePrimaryHandler(handler));
    }
}
