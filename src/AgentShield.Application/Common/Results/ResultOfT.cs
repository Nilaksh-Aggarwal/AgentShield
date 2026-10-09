using System.Diagnostics.CodeAnalysis;

namespace AgentShield.Application.Common.Results;

/// <summary>
/// Outcome of an operation that produces a non-null <typeparamref name="TValue"/> on success.
/// </summary>
[SuppressMessage(
    "Design",
    "CA1000:Do not declare static members on generic types",
    Justification = "Static factories (Result<T>.Success/Failure) are the intended construction API; the non-generic Result.Success<T>/Failure<T> overloads offer type inference.")]
public sealed class Result<TValue> : Result
{
    private readonly TValue? _value;

    private Result(TValue value)
        : base(true, [])
    {
        _value = value;
    }

    private Result(IReadOnlyList<Error> errors)
        : base(false, errors)
    {
    }

    /// <summary>The value of a successful result.</summary>
    /// <exception cref="InvalidOperationException">The result is a failure.</exception>
    public TValue Value => IsSuccess
        ? _value!
        : throw new InvalidOperationException("A failed result has no value. Check IsSuccess before reading Value.");

    public static Result<TValue> Success(TValue value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return new Result<TValue>(value);
    }

    public static new Result<TValue> Failure(Error error)
    {
        ArgumentNullException.ThrowIfNull(error);
        return new Result<TValue>([error]);
    }

    public static new Result<TValue> Failure(IEnumerable<Error> errors) => new(ToErrorList(errors));

    /// <summary>Transforms the value of a success; propagates failures unchanged.</summary>
    public Result<TOut> Map<TOut>(Func<TValue, TOut> map)
    {
        ArgumentNullException.ThrowIfNull(map);
        return IsSuccess ? Result<TOut>.Success(map(Value)) : Result<TOut>.Failure(Errors);
    }

    /// <summary>Chains an operation that may itself fail; propagates failures unchanged.</summary>
    public Result<TOut> Bind<TOut>(Func<TValue, Result<TOut>> bind)
    {
        ArgumentNullException.ThrowIfNull(bind);
        return IsSuccess ? bind(Value) : Result<TOut>.Failure(Errors);
    }

    /// <summary>Asynchronously chains an operation that may itself fail; propagates failures unchanged.</summary>
    public async Task<Result<TOut>> BindAsync<TOut>(Func<TValue, CancellationToken, Task<Result<TOut>>> bind, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(bind);
        return IsSuccess ? await bind(Value, cancellationToken) : Result<TOut>.Failure(Errors);
    }

    /// <summary>Turns a success into a failure when <paramref name="predicate"/> does not hold.</summary>
    public Result<TValue> Ensure(Func<TValue, bool> predicate, Error error)
    {
        ArgumentNullException.ThrowIfNull(predicate);
        ArgumentNullException.ThrowIfNull(error);

        if (IsFailure)
        {
            return this;
        }

        return predicate(Value) ? this : Failure(error);
    }

    public TOut Match<TOut>(Func<TValue, TOut> onSuccess, Func<IReadOnlyList<Error>, TOut> onFailure)
    {
        ArgumentNullException.ThrowIfNull(onSuccess);
        ArgumentNullException.ThrowIfNull(onFailure);

        return IsSuccess ? onSuccess(Value) : onFailure(Errors);
    }

    public static implicit operator Result<TValue>(TValue value) => Success(value);

    public static implicit operator Result<TValue>(Error error) => Failure(error);
}
