using AgentShield.Application.Common.Results;
using FluentValidation.Results;

namespace AgentShield.Application.Common.Validation;

public static class ValidationResultExtensions
{
    /// <summary>
    /// Converts FluentValidation failures into application <see cref="Error"/>s of type
    /// <see cref="ErrorType.Validation"/>. The FluentValidation error code (e.g. <c>NotEmptyValidator</c>)
    /// is exposed as <c>Validation.NotEmpty</c>.
    /// </summary>
    public static IReadOnlyList<Error> ToErrors(this ValidationResult validationResult)
    {
        ArgumentNullException.ThrowIfNull(validationResult);

        return validationResult.Errors
            .Select(failure => Error.Validation(
                failure.PropertyName,
                failure.ErrorMessage,
                ToErrorCode(failure.ErrorCode)))
            .ToArray();
    }

    private static string ToErrorCode(string? validatorCode)
    {
        if (string.IsNullOrWhiteSpace(validatorCode))
        {
            return "Validation.Invalid";
        }

        const string suffix = "Validator";
        var name = validatorCode.EndsWith(suffix, StringComparison.Ordinal)
            ? validatorCode[..^suffix.Length]
            : validatorCode;

        return name.Contains('.', StringComparison.Ordinal) ? name : $"Validation.{name}";
    }
}
