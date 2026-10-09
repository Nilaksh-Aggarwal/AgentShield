using System.Collections.Frozen;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using FluentValidation;

namespace AgentShield.Application.Activity.ListActivity;

/// <summary>A page of the security activity history (query string of <c>GET /api/v1/activity</c>).</summary>
/// <remarks>
/// Filter values are bound as text and accepted only as exact declared names, like enums in a JSON body (ADR 0009): the
/// query-string enum binder would also accept numbers, other casings and comma lists such as <c>Block,Allow</c>.
/// </remarks>
public sealed record ListActivityRequest
{
    public const int DefaultPageSize = 25;
    public const int MaxPageSize = 100;

    /// <summary>Highest page number accepted; with <see cref="MaxPageSize"/> it keeps every offset far inside <c>int</c>.</summary>
    public const int MaxPage = 100_000;

    /// <summary>1-based page number; 1 when omitted. A page after the last one is empty, not an error.</summary>
    public int? Page { get; init; }

    /// <summary>Records per page, 1 to <see cref="MaxPageSize"/>; <see cref="DefaultPageSize"/> when omitted.</summary>
    public int? PageSize { get; init; }

    /// <summary>
    /// Decisions to include, each an exact name (<c>Allow</c>, <c>Review</c>, <c>Block</c>); repeat the parameter for
    /// several. Every decision when omitted.
    /// </summary>
    public IReadOnlyList<string>? Decision { get; init; }

    /// <summary>Lowest risk level to include, an exact name (<c>Low</c> to <c>Critical</c>); every level when omitted.</summary>
    public string? MinRiskLevel { get; init; }

    internal static FrozenDictionary<string, SecurityDecision> DecisionNames { get; } = NamesOf<SecurityDecision>();

    internal static FrozenDictionary<string, RiskLevel> RiskLevelNames { get; } = NamesOf<RiskLevel>();

    private static FrozenDictionary<string, TEnum> NamesOf<TEnum>()
        where TEnum : struct, Enum =>
        Enum.GetValues<TEnum>().ToFrozenDictionary(value => value.ToString(), StringComparer.Ordinal);
}

public sealed class ListActivityRequestValidator : AbstractValidator<ListActivityRequest>
{
    public ListActivityRequestValidator()
    {
        RuleFor(request => request.Page)
            .InclusiveBetween(1, ListActivityRequest.MaxPage)
            .When(request => request.Page is not null);

        RuleFor(request => request.PageSize)
            .InclusiveBetween(1, ListActivityRequest.MaxPageSize)
            .When(request => request.PageSize is not null);

        RuleFor(request => request.Decision)
            .Must(decisions => decisions!.Count <= ListActivityRequest.DecisionNames.Count)
            .WithMessage($"'Decision' can be given at most {ListActivityRequest.DecisionNames.Count} times.")
            .When(request => request.Decision is not null);

        // The messages list the accepted names, never the rejected value.
        RuleForEach(request => request.Decision)
            .Must(decision => decision is not null && ListActivityRequest.DecisionNames.ContainsKey(decision))
            .WithMessage($"'Decision' must be one of: {string.Join(", ", Enum.GetNames<SecurityDecision>())}.");

        RuleFor(request => request.MinRiskLevel)
            .Must(level => ListActivityRequest.RiskLevelNames.ContainsKey(level!))
            .WithMessage($"'Min Risk Level' must be one of: {string.Join(", ", Enum.GetNames<RiskLevel>())}.")
            .When(request => request.MinRiskLevel is not null);
    }
}
