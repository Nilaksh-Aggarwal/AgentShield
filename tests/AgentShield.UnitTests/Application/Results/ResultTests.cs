using AgentShield.Application.Common.Results;

namespace AgentShield.UnitTests.Application.Results;

public class ResultTests
{
    private static readonly Error NotFound = Error.NotFound("Item.NotFound", "Item was not found.");
    private static readonly Error Conflict = Error.Conflict("Item.Conflict", "Item already exists.");

    [Fact]
    public void Success_HasNoErrors_AndReadingErrorThrows()
    {
        var result = Result.Success();

        Assert.True(result.IsSuccess);
        Assert.False(result.IsFailure);
        Assert.Empty(result.Errors);
        Assert.Throws<InvalidOperationException>(() => result.Error);
    }

    [Fact]
    public void Failure_ExposesPrimaryErrorAndAllErrors()
    {
        var result = Result.Failure([NotFound, Conflict]);

        Assert.True(result.IsFailure);
        Assert.Equal(NotFound, result.Error);
        Assert.Equal([NotFound, Conflict], result.Errors);
    }

    [Fact]
    public void Failure_WithoutErrors_IsRejected()
    {
        Assert.Throws<ArgumentException>(() => Result.Failure(Array.Empty<Error>()));
        Assert.Throws<ArgumentException>(() => Result<int>.Failure(Array.Empty<Error>()));
    }

    [Fact]
    public void Failure_WithNullError_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => Result.Failure((Error)null!));
        Assert.Throws<ArgumentException>(() => Result.Failure(new Error[] { NotFound, null! }));
    }

    [Fact]
    public void GenericSuccess_ExposesValue()
    {
        var result = Result.Success("value");

        Assert.True(result.IsSuccess);
        Assert.Equal("value", result.Value);
    }

    [Fact]
    public void GenericSuccess_WithNullValue_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(() => Result.Success<string>(null!));
    }

    [Fact]
    public void GenericFailure_ReadingValueThrows()
    {
        Result<string> result = NotFound;

        Assert.True(result.IsFailure);
        Assert.Throws<InvalidOperationException>(() => result.Value);
    }

    [Fact]
    public void ImplicitConversions_CreateSuccessFromValue_AndFailureFromError()
    {
        Result<int> success = 42;
        Result<int> failure = NotFound;
        Result nonGenericFailure = Conflict;

        Assert.Equal(42, success.Value);
        Assert.Equal(NotFound, failure.Error);
        Assert.Equal(Conflict, nonGenericFailure.Error);
    }

    [Fact]
    public void Map_TransformsSuccess_AndPropagatesFailure()
    {
        var mapped = Result.Success(2).Map(value => value * 10);
        var failed = Result.Failure<int>(NotFound).Map(value => value * 10);

        Assert.Equal(20, mapped.Value);
        Assert.Equal(NotFound, failed.Error);
    }

    [Fact]
    public void Bind_ChainsOperations_AndStopsAtFirstFailure()
    {
        var invoked = false;

        var chained = Result.Success(2).Bind(value => Result.Success(value.ToString(System.Globalization.CultureInfo.InvariantCulture)));
        var failed = Result.Failure<int>(NotFound).Bind(value =>
        {
            invoked = true;
            return Result.Success(value);
        });

        Assert.Equal("2", chained.Value);
        Assert.Equal(NotFound, failed.Error);
        Assert.False(invoked);
    }

    [Fact]
    public async Task BindAsync_ChainsAsynchronousOperations()
    {
        var result = await Result.Success(3)
            .BindAsync((value, _) => Task.FromResult(Result.Success(value + 1)));

        Assert.Equal(4, result.Value);
    }

    [Fact]
    public void Ensure_FailsWhenPredicateDoesNotHold()
    {
        var rule = Error.BusinessRule("Number.Negative", "Number must be positive.");

        Assert.True(Result.Success(5).Ensure(value => value > 0, rule).IsSuccess);
        Assert.Equal(rule, Result.Success(-5).Ensure(value => value > 0, rule).Error);
    }

    [Fact]
    public void Match_SelectsBranchByOutcome()
    {
        Assert.Equal("ok:1", Result.Success(1).Match(value => $"ok:{value}", errors => $"fail:{errors.Count}"));
        Assert.Equal("fail:1", Result.Failure<int>(NotFound).Match(value => $"ok:{value}", errors => $"fail:{errors.Count}"));
    }

    [Fact]
    public void Combine_AggregatesErrorsInOrder()
    {
        var combined = Result.Combine(Result.Success(), Result.Failure(NotFound), Result.Failure(Conflict));

        Assert.Equal([NotFound, Conflict], combined.Errors);
        Assert.True(Result.Combine(Result.Success(), Result.Success()).IsSuccess);
    }
}
