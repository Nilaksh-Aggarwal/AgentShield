namespace AgentShield.Domain.SecurityEvents;

/// <summary>
/// What the AI-assisted analysis stage contributed to one security event: whether it ran, which provider and model
/// answered, how long it took and how many findings it added. Holds no prompt, input or provider response.
/// </summary>
/// <remarks>
/// An audit record must say whether a decision was made with or without the AI signal, so this is recorded for every
/// analysis, including when AI analysis is disabled.
/// </remarks>
public sealed record AiAnalysisSummary
{
    public AiAnalysisSummary(AiAnalysisStatus status, string? provider, string? model, int findingCount, TimeSpan duration)
    {
        if (!Enum.IsDefined(status))
        {
            throw new ArgumentOutOfRangeException(nameof(status), status, "Unknown AI analysis status.");
        }

        if (status != AiAnalysisStatus.Disabled)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(provider);
            ArgumentException.ThrowIfNullOrWhiteSpace(model);
        }

        ArgumentOutOfRangeException.ThrowIfNegative(findingCount);
        ArgumentOutOfRangeException.ThrowIfLessThan(duration, TimeSpan.Zero);

        if (findingCount > 0 && status != AiAnalysisStatus.Completed)
        {
            throw new ArgumentException("Only a completed AI analysis contributes findings.", nameof(findingCount));
        }

        Status = status;
        Provider = status == AiAnalysisStatus.Disabled ? null : provider;
        Model = status == AiAnalysisStatus.Disabled ? null : model;
        FindingCount = findingCount;
        Duration = duration;
    }

    /// <summary>AI analysis was not configured for this analysis.</summary>
    public static AiAnalysisSummary Disabled { get; } = new(AiAnalysisStatus.Disabled, null, null, 0, TimeSpan.Zero);

    public AiAnalysisStatus Status { get; }

    /// <summary>Configured provider identity (e.g. <c>AzureOpenAI</c>); <see langword="null"/> when disabled.</summary>
    public string? Provider { get; }

    /// <summary>Configured model or deployment name; <see langword="null"/> when disabled.</summary>
    public string? Model { get; }

    /// <summary>
    /// Validated findings the provider contributed, before fusion. Excludes the finding that holds an input for review
    /// after a failure.
    /// </summary>
    public int FindingCount { get; }

    /// <summary>Time spent in the stage (disclosure, provider call, validation).</summary>
    public TimeSpan Duration { get; }
}
