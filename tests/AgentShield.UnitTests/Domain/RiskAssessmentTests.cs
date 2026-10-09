using AgentShield.Domain.Risk;

namespace AgentShield.UnitTests.Domain;

public class RiskAssessmentTests
{
    [Theory]
    [InlineData(0, RiskLevel.Low)]
    [InlineData(29, RiskLevel.Low)]
    [InlineData(30, RiskLevel.Medium)]
    [InlineData(69, RiskLevel.Medium)]
    [InlineData(70, RiskLevel.High)]
    [InlineData(89, RiskLevel.High)]
    [InlineData(90, RiskLevel.Critical)]
    [InlineData(100, RiskLevel.Critical)]
    public void Level_IsDerivedFromTheScoreBand(int score, RiskLevel expected)
    {
        Assert.Equal(expected, new RiskAssessment(score).Level);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(101)]
    public void Constructor_ScoreOutsideZeroToHundred_Throws(int score)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => new RiskAssessment(score));
    }

    [Theory]
    [InlineData(RiskLevel.Low)]
    [InlineData(RiskLevel.Medium)]
    [InlineData(RiskLevel.High)]
    [InlineData(RiskLevel.Critical)]
    public void BandBounds_MapBackToTheirLevel(RiskLevel level)
    {
        Assert.Equal(level, new RiskAssessment(RiskAssessment.MinScoreFor(level)).Level);
        Assert.Equal(level, new RiskAssessment(RiskAssessment.MaxScoreFor(level)).Level);
    }

    [Fact]
    public void BandBounds_CoverZeroToHundredWithoutGaps()
    {
        RiskLevel[] levels = [RiskLevel.Low, RiskLevel.Medium, RiskLevel.High, RiskLevel.Critical];

        Assert.Equal(RiskAssessment.MinScore, RiskAssessment.MinScoreFor(levels[0]));
        Assert.Equal(RiskAssessment.MaxScore, RiskAssessment.MaxScoreFor(levels[^1]));
        for (var index = 1; index < levels.Length; index++)
        {
            Assert.Equal(RiskAssessment.MaxScoreFor(levels[index - 1]) + 1, RiskAssessment.MinScoreFor(levels[index]));
        }
    }

    [Fact]
    public void None_IsZeroAndLow()
    {
        Assert.Equal(0, RiskAssessment.None.Score);
        Assert.Equal(RiskLevel.Low, RiskAssessment.None.Level);
    }
}
