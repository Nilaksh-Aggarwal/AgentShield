namespace AgentShield.Application.Common.Results;

/// <summary>
/// Outcome of an operation that is expected to fail in known ways.
/// </summary>
/// <remarks>
/// Invariants: a success carries no errors; a failure carries at least one error.
/// Use exceptions only for unexpected failures — those are handled centrally by the API.
/// A <see cref="Result"/> has no knowledge of HTTP; the API layer maps it to a response.
/// </remarks>
public class Result
{
    private static readonly Result SuccessInstance = new(true, []);

    private protected Result(bool isSuccess, IReadOnlyList<Error> errors)
    {
        IsSuccess = isSuccess;
        Errors = errors;
    }

    public bool IsSuccess { get; }

    public bool IsFailure => !IsSuccess;

    /// <summary>All errors of a failed result; empty on success.</summary>
    public IReadOnlyList<Error> Errors { get; }

    /// <summary>The first (primary) error of a failed result.</summary>
    /// <exception cref="InvalidOperationException">The result is a success.</exception>
    public Error Error => IsFailure
        ? Errors[0]
        : throw new InvalidOperationException("A successful result has no error.");

    public static Result Success() => SuccessInstance;

    public static Result Failure(Error error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return new Result(false, [error]);
    }

    public static Result Failure(IEnumerable<Error> errors) => new(false, ToErrorList(errors));

    public static Result<TValue> Success<TValue>(TValue value) => Result<TValue>.Success(value);

    public static Result<TValue> Failure<TValue>(Error error) => Result<TValue>.Failure(error);

    public static Result<TValue> Failure<TValue>(IEnumerable<Error> errors) => Result<TValue>.Failure(errors);

    /// <summary>
    /// Combines results: success if all succeeded, otherwise a failure carrying every error in order.
    /// </summary>
    public static Result Combine(params IEnumerable<Result> results)
    {
        ArgumentNullException.ThrowIfNull(results);

        var errors = results.SelectMany(result => result.Errors).ToList();
        return errors.Count == 0 ? Success() : Failure(errors);
    }

    public TOut Match<TOut>(Func<TOut> onSuccess, Func<IReadOnlyList<Error>, TOut> onFailure)
    {
        ArgumentNullException.ThrowIfNull(onSuccess);
        ArgumentNullException.ThrowIfNull(onFailure);

        return IsSuccess ? onSuccess() : onFailure(Errors);
    }

    public static implicit operator Result(Error error) => Failure(error);

    private protected static Error[] ToErrorList(IEnumerable<Error> errors)
    {
        ArgumentNullException.ThrowIfNull(errors);

        var list = errors.ToArray();
        if (list.Length == 0)
        {
            throw new ArgumentException("A failed result requires at least one error.", nameof(errors));
        }

        if (Array.Exists(list, error => error is null))
        {
            throw new ArgumentException("Errors cannot contain null.", nameof(errors));
        }

        return list;
    }
}
