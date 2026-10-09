using AgentShield.Application.Common.Results;
using AgentShield.Application.Common.Validation;
using FluentValidation;

namespace AgentShield.UnitTests.Application.Validation;

public class ValidationResultExtensionsTests
{
    private sealed record SampleRequest(string? Content, int Priority);

    private sealed class SampleRequestValidator : AbstractValidator<SampleRequest>
    {
        public SampleRequestValidator()
        {
            RuleFor(request => request.Content).NotEmpty();
            RuleFor(request => request.Priority).InclusiveBetween(1, 5).WithErrorCode("Sample.PriorityOutOfRange");
        }
    }

    [Fact]
    public void ToErrors_ProducesValidationErrorsWithPropertyNamesAndCodes()
    {
        var result = new SampleRequestValidator().Validate(new SampleRequest(Content: "", Priority: 9));

        var errors = result.ToErrors();

        Assert.Equal(2, errors.Count);
        Assert.All(errors, error => Assert.Equal(ErrorType.Validation, error.Type));

        var content = Assert.Single(errors, error => error.PropertyName == "Content");
        Assert.Equal("Validation.NotEmpty", content.Code);

        var priority = Assert.Single(errors, error => error.PropertyName == "Priority");
        Assert.Equal("Sample.PriorityOutOfRange", priority.Code);
    }

    [Fact]
    public void ToErrors_ReturnsEmptyForValidInput()
    {
        var result = new SampleRequestValidator().Validate(new SampleRequest("text", 3));

        Assert.Empty(result.ToErrors());
    }
}
