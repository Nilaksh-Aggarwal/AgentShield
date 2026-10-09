using AgentShield.Infrastructure.AiCapacity;

namespace AgentShield.UnitTests.Infrastructure.AiCapacity;

/// <summary>Startup validation of the AI circuit breaker: every rule, the probe timeout bound, AI disabled.</summary>
public class AiCircuitBreakerOptionsValidatorTests
{
    [Fact]
    public void Validate_CommittedDefaults_Succeed()
    {
        var result = new AiCircuitBreakerOptionsValidator(aiEnabled: true).Validate(null, InMemoryAiCircuitBreakerTests.DefaultOptions());

        Assert.True(result.Succeeded, result.FailureMessage);
    }

    [Theory]
    [InlineData(0, 30, 3, "FailureThreshold must be between 1 and 1000")]
    [InlineData(-1, 30, 3, "FailureThreshold must be between 1 and 1000")]
    [InlineData(1001, 30, 3, "FailureThreshold must be between 1 and 1000")]
    [InlineData(3, 0, 3, "OpenDurationSeconds must be between 1 and 86400")]
    [InlineData(3, 86_401, 3, "OpenDurationSeconds must be between 1 and 86400")]
    [InlineData(3, 30, 0, "HalfOpenProbeTimeoutSeconds must be greater than 0")]
    [InlineData(3, 30, 4, "HalfOpenProbeTimeoutSeconds must not exceed the AI stage's 3 s timeout")]
    public void Validate_AiEnabled_RejectsInvalidSettings(int threshold, int openSeconds, int probeSeconds, string expected)
    {
        var options = new AiCircuitBreakerOptions
        {
            Enabled = true,
            FailureThreshold = threshold,
            OpenDurationSeconds = openSeconds,
            HalfOpenProbeTimeoutSeconds = probeSeconds,
        };

        var result = new AiCircuitBreakerOptionsValidator(aiEnabled: true).Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(expected, result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(AiCircuitBreakerOptions.MaxFailureThreshold, 30)]
    [InlineData(3, AiCircuitBreakerOptions.MaxOpenDurationSeconds)]
    public void Validate_ValuesExactlyAtTheirMaximum_AreAccepted(int threshold, int openSeconds)
    {
        // Both maximums are inclusive (mutation testing: only values one past them were tested).
        var options = new AiCircuitBreakerOptions { Enabled = true, FailureThreshold = threshold, OpenDurationSeconds = openSeconds, HalfOpenProbeTimeoutSeconds = 3 };

        var result = new AiCircuitBreakerOptionsValidator(aiEnabled: true).Validate(null, options);

        Assert.True(result.Succeeded, result.FailureMessage);
    }

    [Fact]
    public void Validate_AiEnabled_EnabledMissing_IsNotInventedAsTrueOrFalse()
    {
        var result = new AiCircuitBreakerOptionsValidator(aiEnabled: true).Validate(null, new AiCircuitBreakerOptions());

        Assert.True(result.Failed);
        Assert.Contains("Ai:CircuitBreaker:Enabled must be set", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_BreakerExplicitlyDisabled_NeedsNoThresholds()
    {
        var result = new AiCircuitBreakerOptionsValidator(aiEnabled: true).Validate(null, new AiCircuitBreakerOptions { Enabled = false });

        Assert.True(result.Succeeded);
    }

    [Fact]
    public void Validate_AiDisabled_SkipsEvenMissingSettings()
    {
        var result = new AiCircuitBreakerOptionsValidator(aiEnabled: false).Validate(null, new AiCircuitBreakerOptions());

        Assert.True(result.Skipped);
    }
}
