using Microsoft.Extensions.Options;

namespace AgentShield.Infrastructure.AiCapacity;

/// <summary>
/// The AI provider circuit breaker (section <c>Ai:CircuitBreaker</c>). Validated at startup when <c>Ai:Enabled</c> is
/// true; see docs/security/ai-analysis.md, section 17. No value has a default in code.
/// </summary>
public sealed class AiCircuitBreakerOptions
{
    public const string SectionName = "Ai:CircuitBreaker";

    /// <summary>
    /// Upper bound for <see cref="HalfOpenProbeTimeoutSeconds"/>: the AI stage's own hard timeout (3 s,
    /// <c>AiAnalysisLimits.Timeout</c> in the Security layer), which always applies on top.
    /// </summary>
    public const int MaxProbeTimeoutSeconds = 3;

    /// <summary>Longest accepted open period (a day); longer would keep AI off for no measurable reason.</summary>
    public const int MaxOpenDurationSeconds = 86_400;

    /// <summary>Largest accepted failure threshold.</summary>
    public const int MaxFailureThreshold = 1_000;

    /// <summary>
    /// When false, every call is allowed and nothing opens the circuit (provider failures still hold their input for
    /// review, one by one, after a full provider call).
    /// </summary>
    public bool? Enabled { get; set; }

    /// <summary>Consecutive provider availability failures (while closed) that open the circuit.</summary>
    public int FailureThreshold { get; set; }

    /// <summary>How long the circuit stays open before one probe call may test the provider again.</summary>
    public int OpenDurationSeconds { get; set; }

    /// <summary>
    /// Timeout of the half-open probe call: at most the AI stage's 3 s bound. The provider's own timeout
    /// (<c>Ai:TimeoutSeconds</c>) applies to the probe as to every call, so the effective bound is the smaller of the two.
    /// A probe that has not reported within this time (plus a second of grace) counts as failed, so the circuit cannot
    /// stay half-open.
    /// </summary>
    public int HalfOpenProbeTimeoutSeconds { get; set; }
}

/// <summary>Startup validation of <see cref="AiCircuitBreakerOptions"/>, only when AI is enabled.</summary>
/// <param name="aiEnabled"><c>Ai:Enabled</c>.</param>
internal sealed class AiCircuitBreakerOptionsValidator(bool aiEnabled) : IValidateOptions<AiCircuitBreakerOptions>
{
    private const string Section = AiCircuitBreakerOptions.SectionName;

    public ValidateOptionsResult Validate(string? name, AiCircuitBreakerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!aiEnabled)
        {
            return ValidateOptionsResult.Skip;
        }

        if (options.Enabled is null)
        {
            return ValidateOptionsResult.Fail($"{Section}:Enabled must be set (true or false).");
        }

        if (options.Enabled == false)
        {
            return ValidateOptionsResult.Success;
        }

        var failures = new List<string>();
        if (options.FailureThreshold is <= 0 or > AiCircuitBreakerOptions.MaxFailureThreshold)
        {
            failures.Add($"{Section}:FailureThreshold must be between 1 and {AiCircuitBreakerOptions.MaxFailureThreshold}.");
        }

        if (options.OpenDurationSeconds is <= 0 or > AiCircuitBreakerOptions.MaxOpenDurationSeconds)
        {
            failures.Add($"{Section}:OpenDurationSeconds must be between 1 and {AiCircuitBreakerOptions.MaxOpenDurationSeconds}.");
        }

        if (options.HalfOpenProbeTimeoutSeconds <= 0)
        {
            failures.Add($"{Section}:HalfOpenProbeTimeoutSeconds must be greater than 0.");
        }

        if (options.HalfOpenProbeTimeoutSeconds > AiCircuitBreakerOptions.MaxProbeTimeoutSeconds)
        {
            failures.Add($"{Section}:HalfOpenProbeTimeoutSeconds must not exceed the AI stage's {AiCircuitBreakerOptions.MaxProbeTimeoutSeconds} s timeout.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }
}
