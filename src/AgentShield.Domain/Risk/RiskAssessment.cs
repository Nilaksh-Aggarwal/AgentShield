namespace AgentShield.Domain.Risk;

/// <summary>
/// The risk of an analysed input as a score from 0 to 100 and the level that score falls in.
/// </summary>
/// <remarks>
/// <para>The level is derived from the score, never set independently, so the two cannot disagree:</para>
/// <list type="table">
/// <item><term>0–29</term><description><see cref="RiskLevel.Low"/></description></item>
/// <item><term>30–69</term><description><see cref="RiskLevel.Medium"/></description></item>
/// <item><term>70–89</term><description><see cref="RiskLevel.High"/></description></item>
/// <item><term>90–100</term><description><see cref="RiskLevel.Critical"/></description></item>
/// </list>
/// <para>This is a prototype scale for ranking and explaining decisions, not a calibrated probability. How findings
/// become a score is the risk engine's job (docs/security/firewall-pipeline.md).</para>
/// </remarks>
public sealed record RiskAssessment
{
    public const int MinScore = 0;
    public const int MaxScore = 100;

    public RiskAssessment(int score)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(score, MinScore);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(score, MaxScore);

        Score = score;
        Level = LevelFor(score);
    }

    /// <summary>An input with no findings.</summary>
    public static RiskAssessment None { get; } = new(MinScore);

    public int Score { get; }

    public RiskLevel Level { get; }

    /// <summary>The lowest score in the band of <paramref name="level"/>.</summary>
    public static int MinScoreFor(RiskLevel level) => level switch
    {
        RiskLevel.Low => 0,
        RiskLevel.Medium => 30,
        RiskLevel.High => 70,
        RiskLevel.Critical => 90,
        _ => throw new ArgumentOutOfRangeException(nameof(level), level, "Unknown risk level."),
    };

    /// <summary>The highest score in the band of <paramref name="level"/>.</summary>
    public static int MaxScoreFor(RiskLevel level) => level switch
    {
        RiskLevel.Low => 29,
        RiskLevel.Medium => 69,
        RiskLevel.High => 89,
        RiskLevel.Critical => MaxScore,
        _ => throw new ArgumentOutOfRangeException(nameof(level), level, "Unknown risk level."),
    };

    private static RiskLevel LevelFor(int score) => score switch
    {
        >= 90 => RiskLevel.Critical,
        >= 70 => RiskLevel.High,
        >= 30 => RiskLevel.Medium,
        _ => RiskLevel.Low,
    };
}
