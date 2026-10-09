using System.Globalization;
using System.Text;
using AgentShield.Evaluation.Dataset;
using AgentShield.Evaluation.Results;

namespace AgentShield.Evaluation.Run;

/// <summary>The summary printed before the first AI request (and by <c>plan</c>, which sends nothing).</summary>
internal static class Preflight
{
    public const string Title = "PRE-FLIGHT: nothing has been sent to the AI provider yet";

    public static string Render(
        EvaluationDataset dataset,
        string inputFingerprint,
        int storedSessions,
        IReadOnlyList<BaselineRecord> baseline,
        string baselineFingerprint,
        string baselineState,
        EvaluationPlan plan,
        SessionOptions options,
        string sessionId,
        IReadOnlyDictionary<string, string> configuration,
        ResultStore store,
        IReadOnlyList<AttemptRecord> attempts)
    {
        var text = new StringBuilder();
        void Row(string name, string value) => text.Append('\n').Append(name.PadRight(16)).Append(value);

        var calls = plan.AiCallsNeeded;
        var perMinute = options.SpacingSeconds > 0 ? 60.0 / options.SpacingSeconds : double.PositiveInfinity;
        text.Append("\n==================== ").Append(Title).Append(" ====================");
        Row("Mode", options.Mode switch
        {
            RunMode.Real => "REAL: Gemini free tier, quota is spent",
            RunMode.Simulated => "SIMULATED: local fake provider on a virtual clock, nothing leaves the process",
            _ => "TEST: fake provider, nothing leaves the process",
        });
        Row("Session", sessionId);
        Row("Dataset", Invariant($"v{dataset.Version}, {dataset.Fixtures.Count} fixtures; input fingerprint {inputFingerprint[..12]} (texts, same as the stored sessions); labels fingerprint {dataset.ContentFingerprint()[..12]}; stored sessions: {storedSessions}"));
        Row("Baseline", Invariant($"recomputed with AI off: {Count(baseline, Labels.Block)} Block / {Count(baseline, Labels.Review)} Review / {Count(baseline, Labels.Allow)} Allow; fingerprint {baselineFingerprint[..12]} ({baselineState})"));
        Row("Model", Invariant($"{configuration.GetValueOrDefault("Ai:Model")} (process override), timeout {configuration.GetValueOrDefault("Ai:TimeoutSeconds")} s, thinking LOW (fixed in code), one attempt per call, no retries"));
        Row("Configuration", "capacity, circuit breaker and timeout checked against the committed appsettings.json: "
            + string.Join("; ", configuration.Where(item => item.Key.StartsWith("Ai:Capacity", StringComparison.Ordinal) || item.Key.StartsWith("Ai:CircuitBreaker", StringComparison.Ordinal))
                .Select(item => item.Key.Replace("Ai:Capacity:", string.Empty, StringComparison.Ordinal).Replace("Ai:", string.Empty, StringComparison.Ordinal) + "=" + item.Value)));
        Row("Gemini key", "configured: " + configuration.GetValueOrDefault("Ai:Gemini:ApiKey configured"));
        Row("Subset", Invariant($"{options.Subset} ({plan.InSubset} fixtures): {plan.AlreadyValid} already have a valid result and are not sent again; {plan.Order.Count} pending"));
        Row("Order", Invariant($"{plan.ZeroCall} deterministic Blocks (zero provider calls, never sent to Gemini) -> {plan.NeverAttempted} never attempted -> {plan.PreviouslyFailed} previously failed (last){(plan.ExcludedFailed > 0 ? Invariant($"; {plan.ExcludedFailed} previously failed excluded") : string.Empty)}"));
        Row("Resend guard", Invariant($"only fixtures without an attempt record and without a send record count as never attempted; {plan.SentWithoutResult} sent without a recorded result (never planned again){(options.ExcludeFailed ? "; previously failed fixtures are excluded, so no fixture is sent twice" : "; previously failed fixtures (recorded failures) are sent again last")}"));
        Row("Provider calls", Invariant($"needed {calls}; HARD CAP {options.MaxCalls} (a request beyond it is refused before sending){(calls > options.MaxCalls ? Invariant($"; {calls - options.MaxCalls} stay pending") : string.Empty)}"));
        Row("Pacing", Invariant($"at least {options.SpacingSeconds} s between calls = at most {perMinute:0.#} per minute{(options.ProviderRpm is { } rpm ? Invariant($"; provider RPM {rpm} -> {100 * perMinute / rpm:0} %") : string.Empty)}"));
        if (options.ProviderRpdRemaining is { } remaining)
        {
            Row("Daily budget", Invariant($"cap {options.MaxCalls} of {remaining} requests left today -> {100.0 * options.MaxCalls / remaining:0} %"));
        }

        Row("Duration", Invariant($"about {Math.Min(calls, options.MaxCalls) * options.SpacingSeconds / 60.0:0} min for the calls{(options.Mode == RunMode.Real ? string.Empty : " (virtual time)")}"));
        var measured = attempts.Where(attempt => attempt.ProviderCall?.PromptTokens is > 0).ToList();
        Row("Tokens", measured.Count == 0
            ? "AgentShield reserves a conservative local estimate per call; no measured usage yet"
            : Invariant($"earlier real calls: {measured.Average(a => a.ProviderCall!.PromptTokens!.Value):0} prompt / {measured.Average(a => a.ProviderCall!.TotalTokens ?? 0):0} total tokens per call; AgentShield reserved {measured.Average(a => (double)a.EstimatedInputTokens):0} (local estimate)"));
        Row("Stop rules", options.StopOnSlowCalls
            ? "first HTTP 429; second 5xx/unavailable; AI timeout; Gemini call >= 2,500 ms; AI stage >= 2,700 ms after the first call; two failed analyses in a row; circuit not Closed; any refused request; API error"
            : "first HTTP 429; second 5xx/unavailable; AI timeout; two failed analyses in a row; circuit not Closed; any refused request; API error (completed calls at or above 2,500 ms are recorded and do not stop the session)");
        Row("Warm-up", options.WarmUp
            ? "before the first fixture, one fixed non-dataset text through a separate host and the local simulator: 0 network requests"
            : "none (the first real call pays the process's start-up cost inside the 3 s timeout)");
        Row("Output", store.Directory + " (fixture IDs, codes, statuses and numbers only)");
        if (options.LogDirectory is { } logs)
        {
            Row("Host logs", logs + " (leak-checked, not kept in the repository)");
        }

        text.Append('\n').Append(new string('=', 20 + Title.Length + 22));
        return text.ToString();
    }

    private static int Count(IReadOnlyList<BaselineRecord> baseline, string decision) => baseline.Count(record => record.Decision == decision);

    private static string Invariant(FormattableString value) => value.ToString(CultureInfo.InvariantCulture);
}
