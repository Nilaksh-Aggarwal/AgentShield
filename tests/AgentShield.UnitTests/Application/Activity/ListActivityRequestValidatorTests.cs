using AgentShield.Application.Activity.ListActivity;
using AgentShield.Application.Common.Validation;

namespace AgentShield.UnitTests.Application.Activity;

public class ListActivityRequestValidatorTests
{
    private readonly ListActivityRequestValidator _validator = new();

    [Fact]
    public void Validate_NothingGiven_PassesWithTheDefaults()
    {
        Assert.True(_validator.Validate(new ListActivityRequest()).IsValid);
    }

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(ListActivityRequest.MaxPage)]
    public void Validate_PageInRange_Passes(int page)
    {
        Assert.True(_validator.Validate(new ListActivityRequest { Page = page }).IsValid);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(int.MinValue)]
    [InlineData(ListActivityRequest.MaxPage + 1)]
    [InlineData(int.MaxValue)]
    public void Validate_PageOutOfRange_FailsOnPage(int page)
    {
        AssertSingleErrorOn(nameof(ListActivityRequest.Page), new ListActivityRequest { Page = page });
    }

    [Theory]
    [InlineData(1)]
    [InlineData(ListActivityRequest.DefaultPageSize)]
    [InlineData(ListActivityRequest.MaxPageSize)]
    public void Validate_PageSizeInRange_Passes(int pageSize)
    {
        Assert.True(_validator.Validate(new ListActivityRequest { PageSize = pageSize }).IsValid);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-5)]
    [InlineData(ListActivityRequest.MaxPageSize + 1)]
    [InlineData(10_000)]
    public void Validate_PageSizeOutOfRange_FailsOnPageSize_SoNoQueryIsUnbounded(int pageSize)
    {
        AssertSingleErrorOn(nameof(ListActivityRequest.PageSize), new ListActivityRequest { PageSize = pageSize });
    }

    [Fact]
    public void Limits_AreTheDocumentedOnes()
    {
        Assert.Equal((25, 100), (ListActivityRequest.DefaultPageSize, ListActivityRequest.MaxPageSize));
    }

    [Theory]
    [InlineData("Allow")]
    [InlineData("Review")]
    [InlineData("Block")]
    public void Validate_ExactDecisionName_Passes(string decision)
    {
        Assert.True(_validator.Validate(new ListActivityRequest { Decision = [decision] }).IsValid);
    }

    [Fact]
    public void Validate_EveryDecisionOnce_Passes()
    {
        Assert.True(_validator.Validate(new ListActivityRequest { Decision = ["Allow", "Review", "Block"] }).IsValid);
    }

    [Theory]
    [InlineData("block")]
    [InlineData("BLOCK")]
    [InlineData(" Block")]
    [InlineData("1")]
    [InlineData("3")]
    [InlineData("Block,Allow")]
    [InlineData("Block, Allow")]
    [InlineData("Sanitize")]
    [InlineData("constructor")]
    [InlineData("")]
    public void Validate_DecisionThatIsNotAnExactName_Fails(string decision)
    {
        var result = _validator.Validate(new ListActivityRequest { Decision = [decision] });

        var error = Assert.Single(result.ToErrors());
        Assert.Equal("Decision[0]", error.PropertyName);
        Assert.Equal("'Decision' must be one of: Allow, Review, Block.", error.Message);
    }

    [Fact]
    public void Validate_MoreDecisionsThanExist_Fails()
    {
        AssertSingleErrorOn(nameof(ListActivityRequest.Decision), new ListActivityRequest { Decision = ["Allow", "Review", "Block", "Block"] });
    }

    [Theory]
    [InlineData("Low")]
    [InlineData("Medium")]
    [InlineData("High")]
    [InlineData("Critical")]
    public void Validate_ExactRiskLevelName_Passes(string level)
    {
        Assert.True(_validator.Validate(new ListActivityRequest { MinRiskLevel = level }).IsValid);
    }

    [Theory]
    [InlineData("high")]
    [InlineData("4")]
    [InlineData("High,Critical")]
    [InlineData("")]
    public void Validate_RiskLevelThatIsNotAnExactName_Fails(string level)
    {
        var error = AssertSingleErrorOn(nameof(ListActivityRequest.MinRiskLevel), new ListActivityRequest { MinRiskLevel = level });

        Assert.Equal("'Min Risk Level' must be one of: Low, Medium, High, Critical.", error.Message);
    }

    [Fact]
    public void Validate_RejectedValues_AreNeverEchoedInTheMessage()
    {
        const string Marker = "zq7-filter-marker";

        var result = _validator.Validate(new ListActivityRequest { Decision = [Marker], MinRiskLevel = Marker });

        Assert.Equal(2, result.Errors.Count);
        Assert.All(result.ToErrors(), error => Assert.DoesNotContain(Marker, error.Message, StringComparison.Ordinal));
    }

    private AgentShield.Application.Common.Results.Error AssertSingleErrorOn(string propertyName, ListActivityRequest request)
    {
        var error = Assert.Single(_validator.Validate(request).ToErrors());
        Assert.Equal(propertyName, error.PropertyName);
        return error;
    }
}
