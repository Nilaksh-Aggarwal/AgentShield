using AgentShield.Evaluation.Dataset;
using AgentShield.Evaluation.Results;

namespace AgentShield.Evaluation.Report;

/// <summary>
/// A confusion matrix. Positives are fixtures labelled Block or Review; what counts as flagged depends on the view (a
/// layer adding a finding, or a final decision other than Allow).
/// </summary>
internal sealed record Confusion(int TruePositives, int FalsePositives, int FalseNegatives, int TrueNegatives)
{
    public int Evaluated => TruePositives + FalsePositives + FalseNegatives + TrueNegatives;

    public double? Precision => TruePositives + FalsePositives == 0 ? null : (double)TruePositives / (TruePositives + FalsePositives);

    public double? Recall => TruePositives + FalseNegatives == 0 ? null : (double)TruePositives / (TruePositives + FalseNegatives);

    /// <summary>Harmonic mean of precision and recall (2TP / (2TP + FP + FN)); null when nothing was positive or flagged.</summary>
    public double? F1 => TruePositives + FalsePositives + FalseNegatives == 0 ? null : 2.0 * TruePositives / ((2 * TruePositives) + FalsePositives + FalseNegatives);

    public static Confusion From(IEnumerable<(bool Positive, bool Flagged)> items)
    {
        var list = items.ToList();
        return new Confusion(
            list.Count(item => item.Positive && item.Flagged),
            list.Count(item => !item.Positive && item.Flagged),
            list.Count(item => item.Positive && !item.Flagged),
            list.Count(item => !item.Positive && !item.Flagged));
    }

    /// <summary>95 % Wilson score interval for <paramref name="successes"/> out of <paramref name="trials"/>.</summary>
    public static (double Low, double High)? Wilson(int successes, int trials)
    {
        if (trials == 0)
        {
            return null;
        }

        const double Z = 1.96;
        var p = (double)successes / trials;
        var denominator = 1 + (Z * Z / trials);
        var centre = (p + (Z * Z / (2 * trials))) / denominator;
        var margin = Z * Math.Sqrt((p * (1 - p) / trials) + (Z * Z / (4.0 * trials * trials))) / denominator;
        return (Math.Max(0, centre - margin), Math.Min(1, centre + margin));
    }
}

/// <summary>Everything known about one fixture: its deterministic result and its attempts.</summary>
internal sealed record FixtureResult(Fixture Fixture, BaselineRecord Baseline, AttemptRecord? Outcome, IReadOnlyList<AttemptRecord> Attempts)
{
    public bool DeterministicFlag => Baseline.Findings.Count > 0;

    /// <summary>The production configuration sends it to the AI (deterministic Blocks skip it).</summary>
    public bool AiEvaluable => Baseline.Decision != Labels.Block;

    public bool AiCompleted => Outcome is { ApiStatus: 200, AiStatus: "Completed" };

    public bool AiFlag => AiCompleted && Outcome!.AiFindings.Count > 0;

    /// <summary>The counted attempt got an answer from the API, but its AI analysis failed (held for review by policy).</summary>
    public bool AiFailed => Outcome is { ApiStatus: 200 } && EvaluationMetrics.IsAiFailure(Outcome.AiStatus);

    /// <summary>The decision of the counted attempt; null when the fixture has not been sent successfully.</summary>
    public string? FinalDecision => Outcome is { ApiStatus: 200 } ? Outcome.Decision : null;

    /// <summary>
    /// Which layer produced the final decision: deterministic decision × AI outcome × final decision. Null when the
    /// fixture has not been sent successfully. Any combination the pipeline must never produce is an integrity violation.
    /// </summary>
    public string? Attribution
    {
        get
        {
            if (FinalDecision is not { } final)
            {
                return null;
            }

            var ai = Outcome!.AiStatus == "NotNeeded" ? "NotNeeded" : AiFlag ? "Finding" : AiCompleted ? "NoFinding" : AiFailed ? "Failed" : "Other";
            return (Baseline.Decision, ai, final) switch
            {
                (Labels.Block, "NotNeeded", Labels.Block) => Attributions.FastPath,
                (Labels.Review, "NoFinding", Labels.Review) => Attributions.DeterministicReview,
                (Labels.Review, "Finding", Labels.Review) => Attributions.AiConcurs,
                (Labels.Review, "Finding", Labels.Block) => Attributions.AiEscalation,
                (Labels.Review, "Failed", Labels.Review) => Attributions.DeterministicReviewAiFailed,
                (Labels.Allow, "Finding", Labels.Review or Labels.Block) => Fixture.Positive ? Attributions.AiCatch : Attributions.AiFalsePositive,
                (Labels.Allow, "Finding", Labels.Allow) => Attributions.AiBelowPolicy,
                (Labels.Allow, "NoFinding", Labels.Allow) => Fixture.Positive ? Attributions.MissedByBoth : Attributions.CleanPass,
                (Labels.Allow, "Failed", Labels.Review) => Attributions.FailSafeHold,
                _ => Attributions.IntegrityViolation,
            };
        }
    }

    /// <summary>The layer that decided the final outcome, in the seven classes of the M14-R2 report; null when not sent.</summary>
    public string? DecidedBy => Attribution switch
    {
        null => null,
        Attributions.FastPath => DecidingLayers.DeterministicBlock,
        Attributions.DeterministicReview or Attributions.AiConcurs or Attributions.DeterministicReviewAiFailed => DecidingLayers.DeterministicReview,
        Attributions.AiEscalation => DecidingLayers.AiBlock,
        Attributions.AiCatch or Attributions.AiFalsePositive => FinalDecision == Labels.Block ? DecidingLayers.AiBlock : DecidingLayers.AiReview,
        Attributions.AiBelowPolicy or Attributions.CleanPass or Attributions.MissedByBoth => DecidingLayers.AiAllow,
        Attributions.FailSafeHold => DecidingLayers.AiFailureReview,
        _ => DecidingLayers.Other,
    };
}

/// <summary>
/// Which layer decided a fixture's final outcome: a deterministic Block or Review stands whatever the AI did; an AI
/// decision is one the completed AI analysis produced (or confirmed, for Allow); a failure is the fail-safe Review.
/// </summary>
internal static class DecidingLayers
{
    public const string DeterministicBlock = "Deterministic Block (AI not invoked)";
    public const string DeterministicReview = "Deterministic Review";
    public const string AiBlock = "AI Block";
    public const string AiReview = "AI Review";
    public const string AiAllow = "AI Allow (AI completed, final Allow)";
    public const string AiFailureReview = "AI failure → Review";
    public const string Other = "Other (must be 0)";

    public static readonly IReadOnlyList<string> All = [DeterministicBlock, DeterministicReview, AiBlock, AiReview, AiAllow, AiFailureReview, Other];
}

/// <summary>Names of the pipeline paths a final decision can come from (Milestone 14 report).</summary>
internal static class Attributions
{
    public const string FastPath = "Deterministic fast path (Block, AI not needed)";
    public const string DeterministicReview = "Deterministic Review, AI found nothing";
    public const string AiConcurs = "Deterministic Review, AI finding, Review stands";
    public const string AiEscalation = "AI escalation (deterministic Review → Block)";
    public const string DeterministicReviewAiFailed = "Deterministic Review, AI failed";
    public const string AiCatch = "AI catch (deterministic Allow → flagged, attack)";
    public const string AiFalsePositive = "AI-induced false positive (deterministic Allow → flagged, benign)";
    public const string AiBelowPolicy = "AI finding below policy (stays Allow)";
    public const string CleanPass = "Clean pass (both allow, benign)";
    public const string MissedByBoth = "Missed by both (both allow, attack)";
    public const string FailSafeHold = "Fail-safe hold (deterministic Allow, AI failed → Review)";
    public const string IntegrityViolation = "Integrity violation (must be 0)";

    public static readonly IReadOnlyList<string> All =
        [FastPath, DeterministicReview, AiConcurs, AiEscalation, DeterministicReviewAiFailed, AiCatch, AiFalsePositive, AiBelowPolicy, CleanPass, MissedByBoth, FailSafeHold, IntegrityViolation];
}

/// <summary>
/// Latency summary. Percentiles use the nearest rank (sorted ascending, P_k = x[⌈k/100 · n⌉]) and are reported only with
/// enough values: the median from <see cref="MinimumForMedian"/>, P95 from <see cref="MinimumForP95"/> (below that,
/// P95 would just be the maximum).
/// </summary>
internal sealed record LatencyStats(int Count, double? Average, double? Min, double? Max, double? P50, double? P95)
{
    public const int MinimumForMedian = 5;

    public const int MinimumForP95 = 20;

    public static LatencyStats From(IEnumerable<double> values)
    {
        var list = values.Order().ToList();
        if (list.Count == 0)
        {
            return new LatencyStats(0, null, null, null, null, null);
        }

        double NearestRank(int percentile) => list[(int)Math.Ceiling(percentile / 100.0 * list.Count) - 1];
        return new LatencyStats(
            list.Count,
            list.Average(),
            list[0],
            list[^1],
            list.Count >= MinimumForMedian ? NearestRank(50) : null,
            list.Count >= MinimumForP95 ? NearestRank(95) : null);
    }
}

/// <summary>Outcomes of every attempt ever made (failed attempts included, even when a later attempt completed).</summary>
internal sealed record AttemptOutcomes(
    int Attempts,
    int ProviderCalls,
    int Completed,
    int NotNeeded,
    int TimedOut,
    int RateLimited,
    int Unavailable,
    int NetworkFailures,
    int MalformedResponses,
    int InvalidResponses,
    int Refused,
    int CapacityExceeded,
    int CircuitOpen,
    int Other)
{
    /// <summary>Provider availability failures other than timeouts: 429, 5xx, network.</summary>
    public int ProviderFailures => RateLimited + Unavailable + NetworkFailures;

    /// <summary>Answers that broke the output contract: malformed (parser) or invalid (validator).</summary>
    public int ContractValidationFailures => MalformedResponses + InvalidResponses;
}

internal sealed record EvaluationMetrics(
    IReadOnlyList<FixtureResult> Fixtures,
    Confusion Deterministic,
    Confusion Ai,
    IReadOnlyList<FixtureResult> AiOnlyDetections,
    IReadOnlyList<FixtureResult> AiMisses,
    IReadOnlyList<FixtureResult> AiFalsePositives,
    IReadOnlyDictionary<(string From, string To), int> Transitions,
    AttemptOutcomes Outcomes,
    LatencyStats AiStage,
    LatencyStats ProviderCall,
    LatencyStats Total,
    LatencyStats TimedOutStage)
{
    public static readonly IReadOnlyList<string> Decisions = [Labels.Allow, Labels.Review, Labels.Block];

    /// <summary>Every AI status that means the AI analysis did not complete (the policy holds the input for review).</summary>
    public static readonly IReadOnlyList<string> FailureStatuses =
        ["TimedOut", "RateLimited", "Unavailable", "NetworkFailure", "MalformedResponse", "InvalidResponse", "Refused", "CapacityExceeded", "CircuitOpen", "ContentWithheld", "UnclassifiedFailure"];

    public int AiEvaluable => Fixtures.Count(result => result.AiEvaluable);

    public int AiCompleted => Fixtures.Count(result => result.AiCompleted);

    public int NotRun => Fixtures.Count(result => result.FinalDecision is null);

    /// <summary>Fixtures with a final decision (sent successfully, AI on).</summary>
    public IReadOnlyList<FixtureResult> Decided => [.. Fixtures.Where(result => result.FinalDecision is not null)];

    /// <summary>
    /// Final decisions with AI off (the deterministic baseline), scored on decisions: flagged = Review or Block, i.e. the
    /// firewall did not allow the input. Over <paramref name="decidedOnly"/> fixtures only, it pairs with <see cref="FinalDecisions"/>.
    /// </summary>
    public Confusion DeterministicDecisions(bool decidedOnly) =>
        Confusion.From((decidedOnly ? Decided : Fixtures).Select(result => (result.Fixture.Positive, Flagged(result.Baseline.Decision))));

    /// <summary>Final decisions with AI on (the counted attempt), scored like <see cref="DeterministicDecisions"/>; fail-safe Reviews count as flagged.</summary>
    public Confusion FinalDecisions => Confusion.From(Decided.Select(result => (result.Fixture.Positive, Flagged(result.FinalDecision))));

    public static bool Flagged(string? decision) => decision is Labels.Review or Labels.Block;

    public static bool IsAiFailure(string? status) => status is not null && FailureStatuses.Contains(status);

    /// <summary>
    /// The counted attempt per fixture is its first valid one (AI completed, or not needed for a deterministic Block);
    /// without one, its latest attempt. Failed attempts still count in <see cref="Outcomes"/>.
    /// </summary>
    public static EvaluationMetrics Compute(EvaluationDataset dataset, IReadOnlyList<BaselineRecord> baseline, IReadOnlyList<AttemptRecord> attempts, Func<Fixture, bool>? include = null)
    {
        ArgumentNullException.ThrowIfNull(dataset);
        ArgumentNullException.ThrowIfNull(baseline);
        ArgumentNullException.ThrowIfNull(attempts);

        var byId = baseline.ToDictionary(record => record.FixtureId, StringComparer.Ordinal);
        var byFixture = attempts.GroupBy(attempt => attempt.FixtureId, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.OrderBy(attempt => attempt.Sequence).ToList(), StringComparer.Ordinal);
        var fixtures = dataset.Fixtures.Where(fixture => include?.Invoke(fixture) ?? true).Select(fixture =>
        {
            var list = byFixture.GetValueOrDefault(fixture.Id) ?? [];
            return new FixtureResult(fixture, byId[fixture.Id], list.Find(attempt => attempt.Valid) ?? list.LastOrDefault(), list);
        }).ToList();

        var transitions = new Dictionary<(string, string), int>();
        foreach (var from in Decisions)
        {
            foreach (var to in Decisions)
            {
                transitions[(from, to)] = fixtures.Count(result => result.Baseline.Decision == from && result.FinalDecision == to);
            }
        }

        var counted = fixtures.SelectMany(result => result.Attempts).ToList();
        int With(string status) => counted.Count(attempt => attempt.AiStatus == status);
        string[] known = ["Completed", "NotNeeded", "TimedOut", "RateLimited", "Unavailable", "NetworkFailure", "MalformedResponse", "InvalidResponse", "Refused", "CapacityExceeded", "CircuitOpen"];
        var outcomes = new AttemptOutcomes(
            counted.Count,
            counted.Sum(attempt => attempt.ProviderCallCount),
            With("Completed"),
            With("NotNeeded"),
            With("TimedOut"),
            With("RateLimited"),
            With("Unavailable"),
            With("NetworkFailure"),
            With("MalformedResponse"),
            With("InvalidResponse"),
            With("Refused"),
            With("CapacityExceeded"),
            With("CircuitOpen"),
            counted.Count(attempt => attempt.AiStatus is null || !known.Contains(attempt.AiStatus)));

        var aiEvaluated = fixtures.Where(result => result.AiCompleted).ToList();
        return new EvaluationMetrics(
            fixtures,
            Confusion.From(fixtures.Select(result => (result.Fixture.Positive, result.DeterministicFlag))),
            Confusion.From(aiEvaluated.Select(result => (result.Fixture.Positive, result.AiFlag))),
            [.. aiEvaluated.Where(result => result.Fixture.Positive && result.AiFlag && !result.DeterministicFlag)],
            [.. aiEvaluated.Where(result => result.Fixture.Positive && !result.AiFlag)],
            [.. aiEvaluated.Where(result => !result.Fixture.Positive && result.AiFlag)],
            transitions,
            outcomes,
            LatencyStats.From(counted.Where(attempt => attempt.AiStatus == "Completed" && attempt.AiStageMs is not null).Select(attempt => attempt.AiStageMs!.Value)),
            LatencyStats.From(counted.Where(attempt => attempt.ProviderCall is { HttpStatus: 200, DurationMs: not null }).Select(attempt => attempt.ProviderCall!.DurationMs!.Value)),
            LatencyStats.From(counted.Where(attempt => attempt.AiStatus == "Completed" && attempt.TotalMs is not null).Select(attempt => attempt.TotalMs!.Value)),
            LatencyStats.From(counted.Where(attempt => attempt.AiStatus == "TimedOut" && attempt.AiStageMs is not null).Select(attempt => attempt.AiStageMs!.Value)));
    }
}
