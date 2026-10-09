using System.Diagnostics;
using System.Globalization;
using System.Text.Json;
using AgentShield.AI;
using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Evaluation.Dataset;
using AgentShield.Evaluation.Hosting;
using AgentShield.Evaluation.Report;
using AgentShield.Evaluation.Results;
using AgentShield.Evaluation.Safety;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AgentShield.Evaluation.Run;

internal enum RunMode
{
    /// <summary>Real Gemini (free tier): quota is spent. Production configuration only.</summary>
    Real,

    /// <summary>A local fake provider on a virtual clock: nothing leaves the process.</summary>
    Simulated,

    /// <summary>Automated tests: a fake provider supplied by the test.</summary>
    Test,
}

internal sealed record SessionOptions
{
    public required RunMode Mode { get; init; }

    public Subset Subset { get; init; } = Subset.All;

    public int MaxCalls { get; init; }

    public int SpacingSeconds { get; init; } = 20;

    public bool ExcludeFailed { get; init; }

    public int? ProviderRpm { get; init; }

    public int? ProviderRpdRemaining { get; init; }

    /// <summary>Print the pre-flight summary and stop before any AI request.</summary>
    public bool PlanOnly { get; init; }

    /// <summary>Working directory for the hosts (their file sink writes logs/ there); null leaves it unchanged.</summary>
    public string? LogDirectory { get; init; }

    /// <summary>Required outside <see cref="RunMode.Real"/>, forbidden in it: the provider is then never contacted.</summary>
    public FakeTransport? FakeTransport { get; init; }

    /// <summary>Extra host settings (tests and simulations only; a real run uses the committed configuration).</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Settings { get; init; } = [];

    /// <summary>The session clock (pacing, durations). Outside real runs it is also the host's <see cref="TimeProvider"/>.</summary>
    public TimeProvider Clock { get; init; } = TimeProvider.System;

    /// <summary>Waits between provider calls; a virtual clock advances instead of waiting.</summary>
    public Func<TimeSpan, CancellationToken, Task> Delay { get; init; } = Task.Delay;

    public TextWriter Output { get; init; } = Console.Error;

    public string? SessionId { get; init; }

    /// <summary>How long to wait (wall clock) for a call the stage abandoned at its timeout to end, so it is recorded.</summary>
    public TimeSpan InFlightGrace { get; init; } = TimeSpan.FromSeconds(10);
}

internal sealed record SessionResult(int ExitCode, EvaluationPlan? Plan, SessionRecord? Session, IReadOnlyList<AttemptRecord> Attempts, IReadOnlyList<string> Problems)
{
    public const int Completed = 0;
    public const int LeakOrIntegrityProblem = 1;
    public const int RefusedBeforeSending = 2;
    public const int StoppedBySafetyRule = 3;
}

internal static class SessionRunner
{
    public const string EvaluatedModel = "gemini-3.5-flash-lite";

    private static readonly string[] NormalEnds = ["all planned fixtures sent", "request cap reached"];

    public static async Task<SessionResult> RunAsync(EvaluationDataset dataset, ResultStore store, SessionOptions options, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(dataset);
        ArgumentNullException.ThrowIfNull(store);
        ArgumentNullException.ThrowIfNull(options);

        void Say(string line) => options.Output.WriteLine("[eval] " + line);
        SessionResult Refuse(IReadOnlyList<string> problems, EvaluationPlan? plan = null)
        {
            foreach (var problem in problems)
            {
                Say("REFUSED (nothing was sent to the provider): " + problem);
            }

            return new SessionResult(SessionResult.RefusedBeforeSending, plan, null, [], problems);
        }

        var problems = Validate(options);
        if (problems.Count > 0)
        {
            return Refuse(problems);
        }

        var previousDirectory = Directory.GetCurrentDirectory();
        if (options.LogDirectory is { } logDirectory)
        {
            Directory.CreateDirectory(logDirectory);
            Directory.SetCurrentDirectory(logDirectory);
        }

        try
        {
            return await RunCoreAsync(dataset, store, options, Say, Refuse, cancellationToken);
        }
        finally
        {
            Directory.SetCurrentDirectory(previousDirectory);
        }
    }

    public static IReadOnlyList<string> Validate(SessionOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        var problems = new List<string>();
        if (options.Mode == RunMode.Real)
        {
            problems.AddRange(SafetyLimits.Check(options.MaxCalls, options.SpacingSeconds, options.ProviderRpm, options.ProviderRpdRemaining));
            if (options.FakeTransport is not null || options.Settings.Count > 0 || options.Clock != TimeProvider.System)
            {
                problems.Add("A real run uses the committed configuration, the system clock and the real provider only.");
            }
        }
        else
        {
            if (options.FakeTransport is null)
            {
                problems.Add("A simulated or test session needs a fake transport (it never contacts the provider).");
            }

            if (options.MaxCalls < 1 || options.SpacingSeconds < 0)
            {
                problems.Add("--max-calls must be at least 1 and the spacing not negative.");
            }
        }

        return problems;
    }

    private static async Task<SessionResult> RunCoreAsync(
        EvaluationDataset dataset,
        ResultStore store,
        SessionOptions options,
        Action<string> say,
        Func<IReadOnlyList<string>, EvaluationPlan?, SessionResult> refuse,
        CancellationToken cancellationToken)
    {
        var started = DateTimeOffset.UtcNow;
        var sessionId = options.SessionId ?? started.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + "-" + options.Mode.ToString().ToLowerInvariant();

        // 1. Stored attempts must come from the same texts (labels only change the scoring, which the report redoes).
        var inputFingerprint = dataset.InputFingerprint();
        var sessions = store.LoadSessions();
        if (sessions.Any(session => session.InputFingerprint != inputFingerprint))
        {
            return refuse(["The stored sessions were produced with different fixture texts (input fingerprint differs)."], null);
        }

        // 2. Deterministic baseline, recomputed now with AI off; it must equal the stored one once attempts exist.
        var baselineRun = await BaselineRunner.RunAsync(dataset);
        if (baselineRun.Problems.Count > 0)
        {
            return refuse(baselineRun.Problems, null);
        }

        var attempts = store.LoadAttempts();
        var stored = store.LoadBaseline();
        var baselineFingerprint = ResultStore.Fingerprint(baselineRun.Records);
        var baselineState = "stored now";
        if (stored.Count > 0 && ResultStore.Fingerprint(stored) == baselineFingerprint)
        {
            baselineState = "matches the stored baseline";
        }
        else if (attempts.Count > 0)
        {
            return refuse(["The deterministic results differ from the stored baseline: the detectors changed since earlier sessions, so results would mix detector versions."], null);
        }
        else
        {
            store.SaveBaseline(baselineRun.Records);
        }

        var baseline = baselineRun.Records.ToDictionary(record => record.FixtureId, StringComparer.Ordinal);
        var plan = Planner.Create(dataset, baseline, attempts, options.Subset, options.ExcludeFailed);

        // 3. The AI host: committed configuration plus the evaluated model (and test settings outside real runs).
        var observer = new ObserverState(options.MaxCalls, options.Clock, options.FakeTransport);
        List<KeyValuePair<string, string>> settings = [new("Ai:Model", EvaluatedModel), .. options.Settings];
        var host = EvaluationHost.Start(new HostSettings(true, settings, options.Mode == RunMode.Real ? null : options.Clock), observer);
        var hostDisposed = false;
        var sessionAttempts = new List<AttemptRecord>();
        var responses = new List<string>();
        var probeResponses = new List<string>();
        var probes = new List<ProbeResult>();
        var configuration = new SortedDictionary<string, string>(StringComparer.Ordinal);
        string? stopReason = null, stopFixture = null;
        string geminiKey;
        try
        {
            var configurationProblems = CheckConfiguration(host, options, configuration, out geminiKey);
            say(Preflight.Render(dataset, inputFingerprint, sessions.Count, baselineRun.Records, baselineFingerprint, baselineState, plan, options, sessionId, configuration, store, attempts));
            if (configurationProblems.Count > 0)
            {
                return refuse(configurationProblems, plan);
            }

            if (options.PlanOnly)
            {
                say("Plan only: no AI request was sent.");
                return new SessionResult(SessionResult.Completed, plan, null, [], []);
            }

            // 4. The paced loop. Nothing is retried; a stop leaves the rest pending for a later session.
            var stopRules = new StopRules();
            long? lastCallStarted = null;
            var index = 0;
            foreach (var item in plan.Order)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var fixture = item.Fixture;
                if (item.NeedsAi && observer.Calls.Count >= options.MaxCalls)
                {
                    (stopReason, stopFixture) = ("request cap reached", fixture.Id);
                    break;
                }

                if (item.NeedsAi && lastCallStarted is { } last)
                {
                    var wait = TimeSpan.FromSeconds(options.SpacingSeconds) - options.Clock.GetElapsedTime(last);
                    if (wait > TimeSpan.Zero)
                    {
                        await options.Delay(wait, cancellationToken);
                    }
                }

                var correlation = "eval-" + sessionId + "-" + fixture.Id;
                var callsBefore = observer.Calls.Count;
                var refusedBefore = observer.Refused;
                var measurementsBefore = host.Metrics.Measurements.Count;
                var before = host.Snapshot();
                var startedUtc = DateTimeOffset.UtcNow;
                var sentAt = options.Clock.GetTimestamp();
                observer.Current = fixture;
                observer.SendAllowed = item.NeedsAi;
                var exchange = await host.PostAsync(fixture.Text, correlation);
                observer.SendAllowed = false;
                await WaitForInFlightAsync(observer, options.InFlightGrace);
                observer.Current = null;

                var after = host.Snapshot();
                var attemptCalls = observer.Calls.Skip(callsBefore).ToList();
                var measurements = host.Metrics.Measurements.Skip(measurementsBefore).ToList();
                var analysis = Analysis.From(exchange, host.Sink, correlation);
                var attempt = new AttemptRecord(
                    sessionId,
                    attempts.Count + sessionAttempts.Count + 1,
                    fixture.Id,
                    startedUtc.ToString("O", CultureInfo.InvariantCulture),
                    baseline[fixture.Id].Decision ?? "unknown",
                    item.NeedsAi,
                    exchange.Status,
                    analysis.Decision,
                    analysis.PolicyRule,
                    analysis.RiskLevel,
                    analysis.RiskScore,
                    analysis.Findings,
                    analysis.AiStatus,
                    analysis.AiFailureRule,
                    Round(analysis.AiStageMs),
                    Round(analysis.AnalysisMs),
                    Round(exchange.Milliseconds),
                    attemptCalls.Count,
                    attemptCalls.Count > 0 ? attemptCalls[0].ToRecord() : null,
                    measurements.Where(m => m.Instrument == "agentshield.ai.input_tokens.reserved").Sum(m => m.Value),
                    string.Join(",", measurements.Where(m => m.Instrument == "agentshield.ai.admissions").Select(m => m.Tags.TrimEnd(';'))),
                    before.Circuit,
                    after.Circuit,
                    attemptCalls.SelectMany(call => call.Descriptions).Any(description => exchange.Body.Contains(description, StringComparison.Ordinal)),
                    analysis.WarningEventIds);
                store.Append(attempt);
                sessionAttempts.Add(attempt);
                responses.Add(exchange.Body + "\n" + exchange.Headers);
                if (attemptCalls.Count > 0)
                {
                    lastCallStarted = sentAt;
                }

                say(Line(++index, plan.Order.Count, attempt));
                stopReason = stopRules.After(attempt, observer.Refused - refusedBefore);
                if (stopReason is not null)
                {
                    stopFixture = fixture.Id;
                    say("STOP: " + stopReason + " (fixture " + fixture.Id + "). Nothing is retried; the remaining fixtures stay pending.");
                    break;
                }
            }

            stopReason ??= "all planned fixtures sent";

            // 5. Error responses with fixture texts in the request (rejected before the pipeline; no provider call).
            observer.SendAllowed = false;
            var callsBeforeProbes = observer.Calls.Count;
            async Task ProbeAsync(string name, string? input, bool withKey, string? rawBody = null)
            {
                var exchange = await host.PostAsync(input, "eval-probe-" + name, withKey, rawBody);
                probeResponses.Add(exchange.Body + "\n" + exchange.Headers);
                var echoed = dataset.Fixtures.Any(fixture => exchange.Body.Contains(fixture.Text, StringComparison.Ordinal) || exchange.Headers.Contains(fixture.Text, StringComparison.Ordinal));
                probes.Add(new ProbeResult(name, exchange.Status, echoed));
            }

            await ProbeAsync("unknown-property-400", null, true, JsonSerializer.Serialize(new { input = dataset.Get("A07").Text, note = true }));
            await ProbeAsync("too-long-422", string.Concat(Enumerable.Repeat(dataset.Get("H01").Text + " ", 400)), true);
            await ProbeAsync("no-api-key-401", dataset.Get("D01").Text, false);
            await ProbeAsync("malformed-json-400", null, true, "{\"input\": " + JsonSerializer.Serialize(dataset.Get("G03").Text));
            if (observer.Calls.Count != callsBeforeProbes)
            {
                stopReason += "; an error probe reached the provider";
            }

            await host.DisposeAsync();
            hostDisposed = true;
        }
        finally
        {
            if (!hostDisposed)
            {
                await host.DisposeAsync();
            }
        }

        // 6. Leak check over everything the session produced (after the hosts and their file sinks shut down).
        var calls = observer.Calls.ToList();
        var check = LeakCheck.ForDataset(dataset);
        check.Add("gemini-api-key", geminiKey, shingles: false);
        for (var i = 0; i < calls.Count; i++)
        {
            // Whole answers exactly (their JSON structure overlaps the API response); model-written descriptions also by
            // six-word runs.
            check.Add(Invariant($"gemini-answer-{i + 1}"), calls[i].AnswerWithFindings, shingles: false);
            for (var j = 0; j < calls[i].Descriptions.Count; j++)
            {
                check.Add(Invariant($"gemini-description-{i + 1}.{j + 1}"), calls[i].Descriptions[j]);
            }
        }

        var logFiles = options.LogDirectory is { } directory && Directory.Exists(directory)
            ? Directory.GetFiles(directory, "*", SearchOption.AllDirectories).Select(file => File.ReadAllText(file)).ToList()
            : [];
        var leaks = check.Run(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal)
        {
            ["logs"] = [.. baselineRun.LogEvents, .. host.Sink.Events.Select(Logs.Render)],
            ["log-files"] = logFiles,
            ["responses"] = [.. baselineRun.Responses, .. responses],
            ["error-responses"] = probeResponses,
            ["metrics"] = [.. host.Metrics.Measurements.Select(m => m.Instrument + "{" + m.Tags + "}")],
            ["attempt-records"] = [.. sessionAttempts.Select(EvaluationJson.Serialize)],
        });
        var leakHits = leaks.Sum(leak => leak.Hits.Values.Sum());
        foreach (var leak in leaks)
        {
            say("LEAK " + leak.Label + ": " + string.Join(", ", leak.Hits.Select(hit => Invariant($"{hit.Key}={hit.Value}"))));
        }

        var warnings = host.Sink.Events.Select(Logs.EventId).Where(id => id is 1100 or 1101 or 1200 or 1201 or 1300)
            .GroupBy(id => id!.Value).ToDictionary(group => group.Key.ToString(CultureInfo.InvariantCulture), group => group.Count(), StringComparer.Ordinal);
        var session = new SessionRecord(
            sessionId, options.Mode.ToString(), started.ToString("O", CultureInfo.InvariantCulture), DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture),
            dataset.Version, inputFingerprint, dataset.ContentFingerprint(), baselineFingerprint, options.Subset.ToString(), options.MaxCalls, options.SpacingSeconds,
            options.ProviderRpm, options.ProviderRpdRemaining, options.ExcludeFailed, configuration, plan.Order.Count, sessionAttempts.Count,
            calls.Count, observer.Refused, stopReason, stopFixture, probes, check.Count, leakHits, leaks, warnings, null);
        store.Append(session);
        store.WriteReport(ReportBuilder.Build(dataset, store.LoadBaseline(), store.LoadAttempts(), store.LoadSessions()));

        say(Invariant($"session {sessionId}: {sessionAttempts.Count} fixtures sent, {calls.Count} provider calls (cap {options.MaxCalls}), refused before sending {observer.Refused}, stop: {stopReason}, leak hits {leakHits}; error probes {string.Join(", ", probes.Select(p => Invariant($"{p.Name}={p.HttpStatus}{(p.Echoed ? " ECHOED" : string.Empty)}")))}"));
        say("results: " + store.Directory);

        var exit = leakHits > 0 || probes.Exists(probe => probe.Echoed) || stopReason.Contains("probe reached", StringComparison.Ordinal)
            ? SessionResult.LeakOrIntegrityProblem
            : NormalEnds.Contains(stopReason) ? SessionResult.Completed : SessionResult.StoppedBySafetyRule;
        return new SessionResult(exit, plan, session, sessionAttempts, []);
    }

    private static List<string> CheckConfiguration(EvaluationHost host, SessionOptions options, SortedDictionary<string, string> configuration, out string geminiKey)
    {
        var ai = host.Services.GetRequiredService<IOptions<AiOptions>>().Value;
        var hostConfiguration = host.Services.GetRequiredService<IConfiguration>();
        geminiKey = hostConfiguration["Ai:Gemini:ApiKey"] ?? string.Empty;
        using (var scope = host.Services.CreateScope())
        {
            configuration["AI provider registered"] = (scope.ServiceProvider.GetService<IAiSecurityAnalyzer>() is not null).ToString(CultureInfo.InvariantCulture);
        }

        configuration["Ai:Enabled"] = ai.Enabled.ToString(CultureInfo.InvariantCulture);
        configuration["Ai:Provider"] = ai.Provider;
        configuration["Ai:Model"] = ai.Model;
        configuration["Ai:TimeoutSeconds"] = ai.TimeoutSeconds.ToString(CultureInfo.InvariantCulture);
        configuration["Ai:Gemini:ApiKey configured"] = (geminiKey.Length > 0).ToString(CultureInfo.InvariantCulture);

        var problems = new List<string>();
        foreach (var (key, committed) in CommittedSettings())
        {
            var actual = hostConfiguration[key] ?? "(missing)";
            configuration[key] = actual;
            if (!string.Equals(actual, committed, StringComparison.OrdinalIgnoreCase))
            {
                problems.Add(Invariant($"{key} is {actual}, but the committed value is {committed}."));
            }
        }

        if (!ai.Enabled || ai.Provider != "Gemini" || ai.Model != EvaluatedModel || ai.TimeoutSeconds != 3)
        {
            problems.Add("AI must be enabled with provider Gemini, model " + EvaluatedModel + " and the 3 s timeout.");
        }

        if (options.Mode == RunMode.Real && geminiKey.Length == 0)
        {
            problems.Add("No Gemini API key is configured (User Secrets Ai:Gemini:ApiKey).");
        }

        return problems;
    }

    /// <summary>Ai:Capacity, Ai:CircuitBreaker and Ai:TimeoutSeconds exactly as committed in appsettings.json.</summary>
    public static IReadOnlyList<KeyValuePair<string, string>> CommittedSettings()
    {
        using var document = JsonDocument.Parse(File.ReadAllText(Paths.ApiAppsettings));
        var ai = document.RootElement.GetProperty("Ai");
        var settings = new List<KeyValuePair<string, string>>();
        Flatten("Ai:Capacity", ai.GetProperty("Capacity"), settings);
        Flatten("Ai:CircuitBreaker", ai.GetProperty("CircuitBreaker"), settings);
        settings.Add(new("Ai:TimeoutSeconds", ai.GetProperty("TimeoutSeconds").GetRawText()));
        return settings;

        static void Flatten(string prefix, JsonElement element, List<KeyValuePair<string, string>> into)
        {
            if (element.ValueKind != JsonValueKind.Object)
            {
                into.Add(new(prefix, element.ValueKind == JsonValueKind.String ? element.GetString()! : element.GetRawText()));
                return;
            }

            foreach (var property in element.EnumerateObject())
            {
                Flatten(prefix + ":" + property.Name, property.Value, into);
            }
        }
    }

    private static async Task WaitForInFlightAsync(ObserverState observer, TimeSpan grace)
    {
        var waited = Stopwatch.StartNew();
        while (observer.InFlight > 0 && waited.Elapsed < grace)
        {
            await Task.Delay(20);
        }
    }

    private static string Line(int index, int total, AttemptRecord attempt)
    {
        var call = attempt.ProviderCall;
        var ai = string.Join(", ", attempt.AiFindings.Select(f => Invariant($"{f.Code} {f.Severity} {f.Confidence:0.##}")));
        return Invariant($"{index,3}/{total} {attempt.FixtureId} {(attempt.ProviderCallAllowed ? "AI " : "det")} {attempt.Decision,-6} AI {attempt.AiStatus,-17} stage {attempt.AiStageMs,7:F0} ms gemini {(call?.HttpStatus?.ToString(CultureInfo.InvariantCulture) ?? (call is null ? "-" : "none")),4} {call?.DurationMs,6:F0} ms est {attempt.EstimatedInputTokens,5} prompt {call?.PromptTokens,4} [{ai}]");
    }

    private static double? Round(double? value) => value is { } number ? Math.Round(number, 1) : null;

    private static string Invariant(FormattableString text) => text.ToString(CultureInfo.InvariantCulture);
}
