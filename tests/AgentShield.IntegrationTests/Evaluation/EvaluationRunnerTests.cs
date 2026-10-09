using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using AgentShield.Evaluation.Dataset;
using AgentShield.Evaluation.Hosting;
using AgentShield.Evaluation.Results;
using AgentShield.Evaluation.Run;
using AgentShield.Evaluation.Safety;
using static AgentShield.IntegrationTests.AiAnalysis.FakeGeminiApi;

namespace AgentShield.IntegrationTests.Evaluation;

/// <summary>
/// The evaluation runner (<c>tests/AgentShield.Evaluation</c>) end to end: real composition with the committed timeout,
/// capacity and circuit settings, a fake provider transport (the observer never forwards anything, so no request can
/// reach Google) and a virtual clock (pacing advances it; the 3 s stage timeout fires exactly). Each test has its own
/// results directory.
/// </summary>
public sealed class EvaluationRunnerTests : IDisposable
{
    private const string FakeKey = "evaluation-runner-tests-key-0000";
    private const string DescriptionMarker = "model-written-marker-51c7e2";

    private static readonly Lazy<EvaluationDataset> Set = new(() => EvaluationDataset.Load(Path.Combine(AppContext.BaseDirectory, "Evaluation", "ai-security-evaluation-set.json")));

    private readonly string _directory = Path.Combine(Path.GetTempPath(), "agentshield-evaluation-tests", Guid.NewGuid().ToString("N"));
    private readonly VirtualClock _clock = new();
    private readonly ConcurrentQueue<string> _sentFixtures = new();

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    [Fact]
    public async Task FullSession_RecordsEveryCall_NeverSendsDeterministicBlocks_AndWritesNoSensitiveData()
    {
        var store = new ResultStore(_directory);

        var result = await RunAsync(store, Answering(finding: true));

        Assert.Equal(SessionResult.Completed, result.ExitCode);
        var session = Assert.IsType<SessionRecord>(result.Session);
        Assert.Equal("all planned fixtures sent", session.StopReason);
        Assert.Equal(Set.Value.Fixtures.Count, result.Attempts.Count);
        Assert.Equal(0, session.LeakHits);
        Assert.All(session.ErrorProbes, probe => Assert.False(probe.Echoed));

        var blocks = result.Attempts.Where(attempt => attempt.DeterministicDecision == Labels.Block).ToList();
        // Counts follow the deterministic rules (28 Blocks since the reliability rules of 2026-10-09; 26 before).
        Assert.Equal(28, blocks.Count);
        Assert.All(blocks, attempt =>
        {
            Assert.False(attempt.ProviderCallAllowed);
            Assert.Equal(0, attempt.ProviderCallCount);
            Assert.Equal(("NotNeeded", Labels.Block), (attempt.AiStatus, attempt.Decision));
        });
        Assert.DoesNotContain(_sentFixtures, id => blocks.Exists(block => block.FixtureId == id));

        // Every provider call: fixture, HTTP status, AI status, durations, findings, decision; one call per fixture.
        var calls = result.Attempts.Where(attempt => attempt.ProviderCallAllowed).ToList();
        Assert.Equal(85, calls.Count);
        Assert.Equal(85, _sentFixtures.Count);
        Assert.Equal(calls.Select(attempt => attempt.FixtureId).Order(StringComparer.Ordinal), _sentFixtures.Order(StringComparer.Ordinal));
        Assert.All(calls, attempt =>
        {
            Assert.Equal((1, ProviderOutcome.Response, 200), (attempt.ProviderCallCount, attempt.ProviderCall!.Outcome, attempt.ProviderCall.HttpStatus));
            Assert.Equal(("Completed", 200), (attempt.AiStatus, attempt.ApiStatus));
            Assert.NotNull(attempt.AiStageMs);
            Assert.NotNull(attempt.TotalMs);
            Assert.NotNull(attempt.ProviderCall.DurationMs);
            Assert.Equal((470, 510, true), (attempt.ProviderCall.PromptTokens, attempt.ProviderCall.TotalTokens, attempt.ProviderCall.AnswerHasOnlyFindings));
            Assert.True(attempt.EstimatedInputTokens > attempt.ProviderCall.PromptTokens);
            Assert.Contains(attempt.AiFindings, finding => finding.Code == "InstructionOverride.AiDetected");
            Assert.Equal(Labels.Block, attempt.Decision);
            Assert.False(attempt.DescriptionInResponse);
            Assert.Equal(("Closed", "Closed"), (attempt.CircuitBefore, attempt.CircuitAfter));
        });

        // Nothing sensitive in any artifact: inputs, hidden payloads, keys, prompt, the model-written description.
        var check = LeakCheck.ForDataset(Set.Value);
        check.Add("fake-gemini-key", FakeKey, shingles: false);
        check.Add("description", DescriptionMarker, shingles: false);
        Assert.All(check.ScanFiles(store.ArtifactFiles()), file => Assert.Empty(file.Labels));
        Assert.Equal(["attempts.jsonl", "baseline.jsonl", "report.md", "sessions.jsonl"], store.ArtifactFiles().Select(Path.GetFileName));
    }

    [Fact]
    public async Task Resume_SendsOnlyFixturesWithoutAValidResult_AndNeverResendsCompletedOnes()
    {
        var store = new ResultStore(_directory);

        var first = await RunAsync(store, Answering(finding: false), subset: Subset.Attacks, maxCalls: 3);
        var sentFirst = _sentFixtures.ToHashSet(StringComparer.Ordinal);
        _sentFixtures.Clear();
        var second = await RunAsync(store, Answering(finding: false), subset: Subset.Attacks);

        Assert.Equal(("request cap reached", SessionResult.Completed), (first.Session!.StopReason, first.ExitCode));
        Assert.Equal(3, sentFirst.Count);
        Assert.Equal(first.Attempts.Count, second.Plan!.AlreadyValid);
        Assert.Equal((0, 0), (second.Plan.ZeroCall, second.Plan.PreviouslyFailed));
        Assert.Empty(_sentFixtures.Intersect(sentFirst));
        Assert.Equal(38, _sentFixtures.Count);

        // Every attack fixture has exactly one attempt, all valid; no benign fixture was sent.
        var attempts = store.LoadAttempts();
        var attacks = Set.Value.Fixtures.Where(fixture => fixture.InAttackCategory).Select(fixture => fixture.Id).Order(StringComparer.Ordinal);
        Assert.Equal(attacks, attempts.Select(attempt => attempt.FixtureId).Order(StringComparer.Ordinal));
        Assert.All(attempts, attempt => Assert.True(attempt.Valid));
        Assert.Equal(2, store.LoadSessions().Count);
    }

    [Fact]
    public async Task Resume_TriesPreviouslyFailedFixturesLast_AndSkipsThemWhenExcluded()
    {
        var store = new ResultStore(_directory);
        string? failed = null;
        FakeTransport failFirst = (request, fixture, token) =>
        {
            failed ??= fixture!.Id;
            return fixture!.Id == failed
                ? Task.FromResult(Json(HttpStatusCode.ServiceUnavailable, ErrorBody(503, "UNAVAILABLE", "Overloaded.")))
                : Answering(finding: false)(request, fixture, token);
        };

        await RunAsync(store, failFirst, subset: Subset.Benign, maxCalls: 3);
        var excluded = await RunAsync(store, Answering(finding: false), subset: Subset.Benign, maxCalls: 3, excludeFailed: true);
        var resumed = await RunAsync(store, Answering(finding: false), subset: Subset.Benign);

        Assert.Equal((1, 0), (excluded.Plan!.ExcludedFailed, excluded.Plan.PreviouslyFailed));
        Assert.DoesNotContain(excluded.Attempts, attempt => attempt.FixtureId == failed);
        var last = resumed.Plan!.Order[^1];
        Assert.Equal((failed, 1), (last.Fixture.Id, last.PreviousAttempts));
        Assert.Equal(["Unavailable", "Completed"], store.LoadAttempts().Where(attempt => attempt.FixtureId == failed).Select(attempt => attempt.AiStatus));
    }

    [Fact]
    public async Task Timeout_IsRecordedWithoutAResponse_StopsTheSession_AndIsNotRetried()
    {
        var store = new ResultStore(_directory);
        var calls = 0;
        FakeTransport stalls = async (_, _, token) =>
        {
            Interlocked.Increment(ref calls);
            _clock.Advance(TimeSpan.FromSeconds(3.1));
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, token);
            }
            catch (OperationCanceledException)
            {
                // Like a real abandoned HTTP call: it ends a little after the stage has already given up (the Milestone 7
                // session-1 gap: the runner must still record this call with its fixture).
                await Task.Delay(TimeSpan.FromMilliseconds(200), CancellationToken.None);
                throw;
            }

            throw new InvalidOperationException("Unreachable: the stage timeout cancels the call.");
        };

        var result = await RunAsync(store, stalls, subset: Subset.Benign);

        Assert.Equal(1, calls);
        Assert.Equal(SessionResult.StoppedBySafetyRule, result.ExitCode);
        Assert.Equal("AI analysis timed out", result.Session!.StopReason);
        var timedOut = result.Attempts[^1];
        Assert.Equal(result.Session.StopFixtureId, timedOut.FixtureId);
        Assert.Equal(("TimedOut", "AI-FAIL/TimedOut"), (timedOut.AiStatus, timedOut.AiFailureRule));
        Assert.Equal((1, ProviderOutcome.NoResponse, (int?)null), (timedOut.ProviderCallCount, timedOut.ProviderCall!.Outcome, timedOut.ProviderCall.HttpStatus));
        Assert.True(timedOut.AiStageMs >= 3_000);
        Assert.Equal(Labels.Review, timedOut.Decision);
        Assert.Single(store.LoadAttempts(), attempt => attempt.FixtureId == timedOut.FixtureId);
    }

    [Fact]
    public async Task RateLimit_StopsAtTheFirst429()
    {
        var store = new ResultStore(_directory);

        var result = await RunAsync(store, (_, _, _) => Task.FromResult(Json(HttpStatusCode.TooManyRequests, ErrorBody(429, "RESOURCE_EXHAUSTED", "Quota exceeded."))));

        Assert.Single(_sentFixtures);
        Assert.Equal(("HTTP 429 from Gemini (rate limited)", SessionResult.StoppedBySafetyRule), (result.Session!.StopReason, result.ExitCode));
        Assert.Equal((429, "RateLimited"), (result.Attempts[^1].ProviderCall!.HttpStatus, result.Attempts[^1].AiStatus));
    }

    [Fact]
    public async Task ServiceUnavailable_StopsAtTheSecond503_WithoutRetryingEither()
    {
        var store = new ResultStore(_directory);

        var result = await RunAsync(store, (_, _, _) => Task.FromResult(Json(HttpStatusCode.ServiceUnavailable, ErrorBody(503, "UNAVAILABLE", "Overloaded."))));

        Assert.Equal(2, _sentFixtures.Count);
        Assert.Equal(2, _sentFixtures.Distinct().Count());
        Assert.StartsWith("second HTTP 5xx", result.Session!.StopReason, StringComparison.Ordinal);
        var failures = result.Attempts.Where(attempt => attempt.ProviderCallAllowed).ToList();
        Assert.Equal(2, failures.Count);
        Assert.All(failures, attempt => Assert.Equal((1, 503, "Unavailable"), (attempt.ProviderCallCount, attempt.ProviderCall!.HttpStatus, attempt.AiStatus)));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(4)]
    public async Task HardCap_IsNeverExceeded(int maxCalls)
    {
        var store = new ResultStore(_directory);

        var result = await RunAsync(store, Answering(finding: false), maxCalls: maxCalls);

        Assert.Equal(maxCalls, _sentFixtures.Count);
        Assert.Equal(maxCalls, result.Session!.ProviderCalls);
        Assert.Equal(("request cap reached", SessionResult.Completed), (result.Session.StopReason, result.ExitCode));
    }

    [Fact]
    public async Task Preflight_IsPrintedBeforeTheFirstProviderRequest_AndPlanOnlySendsNothing()
    {
        using var planOutput = new StringWriter();
        var plan = await RunAsync(new ResultStore(Path.Combine(_directory, "plan")), Answering(finding: false), planOnly: true, output: planOutput);
        Assert.Empty(_sentFixtures);
        Assert.Empty(plan.Attempts);
        Assert.Null(plan.Session);
        Assert.Contains(Preflight.Title, planOutput.ToString(), StringComparison.Ordinal);
        Assert.Contains("HARD CAP 150", planOutput.ToString(), StringComparison.Ordinal);

        using var runOutput = new StringWriter();
        bool? printedBeforeFirstCall = null;
        FakeTransport watching = (request, fixture, token) =>
        {
            printedBeforeFirstCall ??= runOutput.ToString().Contains(Preflight.Title, StringComparison.Ordinal);
            return Answering(finding: false)(request, fixture, token);
        };
        await RunAsync(new ResultStore(Path.Combine(_directory, "run")), watching, maxCalls: 1, output: runOutput);
        Assert.True(printedBeforeFirstCall);
    }

    [Fact]
    public async Task ChangedDeterministicResults_OrChangedFixtures_AreRefusedBeforeAnyRequest()
    {
        var store = new ResultStore(_directory);
        await RunAsync(store, Answering(finding: false), maxCalls: 1);
        _sentFixtures.Clear();

        // A stored baseline from different detectors (one decision changed) must not be mixed with a new run.
        var baseline = store.LoadBaseline().ToList();
        baseline[0] = baseline[0] with { Decision = baseline[0].Decision == Labels.Allow ? Labels.Review : Labels.Allow };
        store.SaveBaseline(baseline);
        var changedDetectors = await RunAsync(store, Answering(finding: false));

        // Results from different fixture content must not be mixed either.
        var other = new ResultStore(Path.Combine(_directory, "other"));
        other.Append(store.LoadSessions()[0] with { InputFingerprint = new string('0', 64) });
        var changedFixtures = await RunAsync(other, Answering(finding: false));

        Assert.Equal(SessionResult.RefusedBeforeSending, changedDetectors.ExitCode);
        Assert.Equal(SessionResult.RefusedBeforeSending, changedFixtures.ExitCode);
        Assert.Empty(_sentFixtures);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────────────────────────────────────────

    private Task<SessionResult> RunAsync(
        ResultStore store,
        FakeTransport transport,
        Subset subset = Subset.All,
        int maxCalls = 150,
        bool excludeFailed = false,
        bool planOnly = false,
        TextWriter? output = null)
    {
        FakeTransport recording = (request, fixture, token) =>
        {
            _sentFixtures.Enqueue(fixture?.Id ?? "(none)");
            return transport(request, fixture, token);
        };

        return SessionRunner.RunAsync(Set.Value, store, new SessionOptions
        {
            Mode = RunMode.Test,
            Subset = subset,
            MaxCalls = maxCalls,
            SpacingSeconds = 20,
            ExcludeFailed = excludeFailed,
            PlanOnly = planOnly,
            FakeTransport = recording,
            Settings = [new("Ai:Gemini:ApiKey", FakeKey)],
            Clock = _clock,
            Delay = (wait, _) =>
            {
                _clock.Advance(wait);
                return Task.CompletedTask;
            },
            Output = output ?? TextWriter.Null,
        });
    }

    /// <summary>A contract-valid Gemini answer with usage metadata; with a finding whose description is model-written text.</summary>
    private static FakeTransport Answering(bool finding) => (_, _, _) =>
    {
        object[] findings = finding
            ? [new { category = "InstructionOverride", code = "InstructionOverride.AiDetected", severity = "High", confidence = 0.9, description = "Asks to drop rules " + DescriptionMarker }]
            : [];
        var envelope = JsonSerializer.Serialize(new
        {
            candidates = new[] { new { content = new { role = "model", parts = new[] { new { text = JsonSerializer.Serialize(new { findings }) } } }, finishReason = "STOP" } },
            usageMetadata = new { promptTokenCount = 470, candidatesTokenCount = 40, totalTokenCount = 510 },
            modelVersion = "fake",
        });
        return Task.FromResult(Json(HttpStatusCode.OK, envelope));
    };
}
