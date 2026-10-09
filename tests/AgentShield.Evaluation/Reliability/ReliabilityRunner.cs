using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using AgentShield.Evaluation.Dataset;
using AgentShield.Evaluation.Hosting;
using Serilog.Events;

namespace AgentShield.Evaluation.Reliability;

/// <summary>How a reliability run configures the AI stage. Neither mode sends anything to Google.</summary>
internal enum ReliabilityMode
{
    /// <summary>AI off: the deterministic pipeline alone decides (provider cap 0).</summary>
    Deterministic,

    /// <summary>AI on with a simulated provider outage (HTTP 503, no network): what an unavailable Gemini decides.</summary>
    AiUnavailable,
}

/// <summary>One fixture's result: IDs, codes and statuses only, never the input.</summary>
internal sealed record ReliabilityOutcome(string Id, string Category, string Label, int Status, string? Decision, IReadOnlyList<string> Codes, string? AiStatus)
{
    public bool Detected => Decision is not null and not Labels.Allow;
}

internal sealed record ReliabilityRun(
    string Label,
    string Split,
    string DatasetFingerprint,
    string Mode,
    DateTimeOffset RanAt,
    int ProviderNetworkRequests,
    int SimulatedProviderResponses,
    IReadOnlyList<ReliabilityOutcome> Outcomes);

internal sealed record Confusion(int TruePositives, int FalseNegatives, int FalsePositives, int TrueNegatives, int Errors)
{
    public int Positives => TruePositives + FalseNegatives;

    public int Negatives => FalsePositives + TrueNegatives;

    public double? Precision => TruePositives + FalsePositives == 0 ? null : (double)TruePositives / (TruePositives + FalsePositives);

    public double? Recall => Positives == 0 ? null : (double)TruePositives / Positives;

    public double? FalsePositiveRate => Negatives == 0 ? null : (double)FalsePositives / Negatives;

    public static Confusion Of(IEnumerable<ReliabilityOutcome> outcomes)
    {
        int tp = 0, fn = 0, fp = 0, tn = 0, errors = 0;
        foreach (var outcome in outcomes)
        {
            if (outcome.Status != 200)
            {
                errors++;
            }
            else if (outcome.Label != Labels.Allow)
            {
                if (outcome.Detected) { tp++; } else { fn++; }
            }
            else
            {
                if (outcome.Detected) { fp++; } else { tn++; }
            }
        }

        return new Confusion(tp, fn, fp, tn, errors);
    }
}

internal sealed record StressResult(
    int Hosts,
    int Concurrency,
    int Rounds,
    int BurnThreads,
    int Requests,
    int NonSuccess,
    IReadOnlyDictionary<string, int> StatusCounts,
    IReadOnlyDictionary<string, int> ServerExceptions,
    int DecisionMismatches,
    double P50Ms,
    double P95Ms,
    double MaxMs);

/// <summary>
/// Runs a reliability set through the real API composition in process (tests/Evaluation/reliability/README.md). The
/// results hold IDs, labels, decisions, finding codes and statuses only.
/// </summary>
internal static class ReliabilityRunner
{
    private const string SimulatedKey = "simulated-key-not-real-0000";

    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    public static string ResultsDirectory => Path.Combine(ReliabilityDataset.Directory, "results");

    public static async Task<ReliabilityRun> RunAsync(ReliabilityDataset dataset, ReliabilityMode mode, string label)
    {
        ArgumentNullException.ThrowIfNull(dataset);

        var observer = mode == ReliabilityMode.Deterministic
            ? new ObserverState(maxCalls: 0, TimeProvider.System, (_, _, _) => throw new HttpRequestException("No provider call is allowed in a deterministic run."))
            : new ObserverState(maxCalls: int.MaxValue, TimeProvider.System, (_, _, _) => Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable)));
        observer.SendAllowed = mode == ReliabilityMode.AiUnavailable;
        var settings = mode == ReliabilityMode.Deterministic
            ? new HostSettings(false, [new("Ai:Gemini:ApiKey", string.Empty)], null)
            : new HostSettings(true, [new("Ai:Gemini:ApiKey", SimulatedKey)], null);

        var outcomes = new List<ReliabilityOutcome>();
        var host = EvaluationHost.Start(settings, observer);
        await using (host)
        {
            foreach (var fixture in dataset.Fixtures)
            {
                var correlation = "reliability-" + fixture.Id;
                var exchange = await host.PostAsync(fixture.Text, correlation);
                var analysis = Analysis.From(exchange, host.Sink, correlation);
                outcomes.Add(new ReliabilityOutcome(
                    fixture.Id,
                    fixture.Category,
                    fixture.Label,
                    exchange.Status,
                    analysis.Decision,
                    [.. analysis.Findings.Select(finding => finding.Code)],
                    analysis.AiStatus));
            }
        }

        // With a fake transport the observer answers every permitted call itself and never forwards to the network.
        return new ReliabilityRun(
            label,
            dataset.Split,
            dataset.ContentFingerprint(),
            mode == ReliabilityMode.Deterministic ? "deterministic (AI off)" : "AI on, provider unavailable (simulated HTTP 503, no network)",
            DateTimeOffset.UtcNow,
            ProviderNetworkRequests: 0,
            SimulatedProviderResponses: observer.Calls.Count,
            outcomes);
    }

    /// <summary>
    /// Several hosts at once, each sending every fixture with the given concurrency for several rounds, optionally with
    /// CPU-burning threads: any non-200 is reported with the exception types the hosts logged. AI off.
    /// </summary>
    public static async Task<StressResult> StressAsync(IReadOnlyList<ReliabilityFixture> fixtures, int hosts, int concurrency, int rounds, int burnThreads)
    {
        ArgumentNullException.ThrowIfNull(fixtures);

        using var stop = new CancellationTokenSource();
        // Dedicated threads (LongRunning), so the burners load the CPU without starving the thread pool the hosts use.
        var burners = Enumerable.Range(0, burnThreads).Select(_ => Task.Factory.StartNew(() =>
        {
            var spin = 0UL;
            while (!stop.IsCancellationRequested)
            {
                spin = unchecked((spin * 6364136223846793005UL) + 1442695040888963407UL);
            }

            return spin;
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default)).ToList();

        var statuses = new ConcurrentDictionary<string, int>();
        var latencies = new ConcurrentBag<double>();
        var mismatches = 0;
        var started = Enumerable.Range(0, hosts)
            .Select(_ => EvaluationHost.Start(
                // The limiter is configuration, not the analysis path under test: raised as in the API test hosts.
                new HostSettings(false, [new("Ai:Gemini:ApiKey", string.Empty), new("RateLimiting:Firewall:PermitLimit", "100000")], null),
                new ObserverState(0, TimeProvider.System, (_, _, _) => throw new HttpRequestException("No provider call is allowed."))))
            .ToList();
        try
        {
            // Reference decisions, sequentially, before the load.
            var reference = new Dictionary<string, string?>(StringComparer.Ordinal);
            foreach (var fixture in fixtures)
            {
                var exchange = await started[0].PostAsync(fixture.Text, "stress-ref-" + fixture.Id);
                reference[fixture.Id] = Analysis.From(exchange, started[0].Sink, "stress-ref-" + fixture.Id).Decision;
            }

            await Parallel.ForEachAsync(
                started.SelectMany((host, index) => Enumerable.Range(0, rounds).SelectMany(round => fixtures.Select(fixture => (host, fixture, tag: $"stress-{index}-{round}-{fixture.Id}")))),
                new ParallelOptions { MaxDegreeOfParallelism = concurrency * hosts },
                async (work, _) =>
                {
                    var exchange = await work.host.PostAsync(work.fixture.Text, work.tag);
                    latencies.Add(exchange.Milliseconds);
                    statuses.AddOrUpdate(exchange.Status.ToString(CultureInfo.InvariantCulture), 1, (_, count) => count + 1);
                    if (exchange.Status == 200)
                    {
                        using var document = JsonDocument.Parse(exchange.Body);
                        var decision = document.RootElement.GetProperty("data").GetProperty("decision").GetString();
                        if (decision != reference[work.fixture.Id])
                        {
                            Interlocked.Increment(ref mismatches);
                        }
                    }
                });
        }
        finally
        {
            await stop.CancelAsync();
            await Task.WhenAll(burners);
        }

        var exceptions = started
            .SelectMany(host => host.Sink.Events)
            .Where(entry => entry.Level >= LogEventLevel.Error)
            .Select(entry => entry.Exception?.GetType().FullName ?? Logs.Scalar(entry, "ExceptionType") ?? entry.MessageTemplate.Text)
            .GroupBy(name => name, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.Count(), StringComparer.Ordinal);
        foreach (var host in started)
        {
            await host.DisposeAsync();
        }

        var ordered = latencies.Order().ToArray();
        double Percentile(double p) => ordered.Length == 0 ? 0 : ordered[Math.Clamp((int)Math.Ceiling(p * ordered.Length) - 1, 0, ordered.Length - 1)];
        var requests = ordered.Length;
        return new StressResult(
            hosts,
            concurrency,
            rounds,
            burnThreads,
            requests,
            requests - statuses.GetValueOrDefault("200"),
            new SortedDictionary<string, int>(statuses, StringComparer.Ordinal),
            exceptions,
            mismatches,
            Math.Round(Percentile(0.50), 1),
            Math.Round(Percentile(0.95), 1),
            Math.Round(ordered.LastOrDefault(), 1));
    }

    public static string Save<T>(T value, string fileName)
    {
        System.IO.Directory.CreateDirectory(ResultsDirectory);
        var path = Path.Combine(ResultsDirectory, fileName);
        File.WriteAllText(path, JsonSerializer.Serialize(value, Indented) + "\n", new UTF8Encoding(false));
        return path;
    }

    public static ReliabilityRun? LoadRun(string fileName)
    {
        var path = Path.Combine(ResultsDirectory, fileName);
        return File.Exists(path) ? JsonSerializer.Deserialize<ReliabilityRun>(File.ReadAllText(path)) : null;
    }

    public static string RunFile(string label, string split, ReliabilityMode mode) =>
        $"{label}-{split}-{(mode == ReliabilityMode.Deterministic ? "deterministic" : "ai-unavailable")}.json";

}
