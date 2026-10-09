using FluentValidation;

namespace AgentShield.Application.Firewall.AnalyzeInput;

/// <summary>Untrusted content to analyse before it is sent to an AI model or agent.</summary>
/// <param name="Input">The content, e.g. a user prompt. Required; at most <see cref="MaxInputLength"/> characters.</param>
public sealed record AnalyzeInputRequest(string? Input)
{
    /// <summary>
    /// Maximum input length in UTF-16 code units. Well below the 1 MiB body limit, and it bounds detection time.
    /// </summary>
    public const int MaxInputLength = 32_000;
}

public sealed class AnalyzeInputRequestValidator : AbstractValidator<AnalyzeInputRequest>
{
    public const string InputTooLargeCode = "Firewall.InputTooLarge";

    public AnalyzeInputRequestValidator()
    {
        RuleFor(request => request.Input)
            .NotEmpty()
            .MaximumLength(AnalyzeInputRequest.MaxInputLength)
            .WithErrorCode(InputTooLargeCode);
    }
}
