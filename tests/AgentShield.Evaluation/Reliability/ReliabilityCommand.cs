using System.Globalization;
using System.Text;

namespace AgentShield.Evaluation.Reliability;

/// <summary>
/// <c>reliability</c>, <c>reliability-stress</c> and <c>reliability-report</c>: deterministic and simulated-outage runs of
/// the reliability sets, a concurrency check, and the comparison report. None of them can send a request to Google.
/// </summary>
internal static class ReliabilityCommand
{
    private const string Usage =
        "usage: reliability --label baseline|final [--split heldout|tuning|legacy-v1|all] [--mode deterministic|ai-unavailable] | reliability-stress [--hosts N] [--concurrency N] [--rounds N] [--burn N] | reliability-report";

    public static async Task<int> RunAsync(string[] args)
    {
        var options = new Dictionary<string, string>(StringComparer.Ordinal);
        for (var i = 1; i < args.Length; i++)
        {
            if (!args[i].StartsWith("--", StringComparison.Ordinal) || i + 1 >= args.Length)
            {
                return Fail("Unexpected argument " + args[i] + ".");
            }

            options[args[i][2..]] = args[++i];
        }

        switch (args[0])
        {
            case "reliability":
                return await RunSetsAsync(options);
            case "reliability-stress":
                return await StressAsync(options);
            case "reliability-report":
                Console.Error.WriteLine("[reliability] report written: " + WriteReport());
                return 0;
            default:
                return Fail("Unknown command " + args[0] + ".");
        }
    }

    private static async Task<int> RunSetsAsync(Dictionary<string, string> options)
    {
        if (!options.TryGetValue("label", out var label) || label is not ("baseline" or "final"))
        {
            return Fail("--label must be baseline or final.");
        }

        var mode = options.GetValueOrDefault("mode", "deterministic") switch
        {
            "deterministic" => ReliabilityMode.Deterministic,
            "ai-unavailable" => ReliabilityMode.AiUnavailable,
            _ => (ReliabilityMode?)null,
        };
        if (mode is null)
        {
            return Fail("--mode must be deterministic or ai-unavailable.");
        }

        var split = options.GetValueOrDefault("split", "all");
        string[] splits = split == "all" ? [ReliabilityDataset.HeldOut, ReliabilityDataset.Tuning, ReliabilityDataset.Legacy] : [split];
        if (splits.Any(s => s is not (ReliabilityDataset.HeldOut or ReliabilityDataset.Tuning or ReliabilityDataset.Legacy)))
        {
            return Fail("--split must be heldout, tuning, legacy-v1 or all.");
        }

        foreach (var name in splits)
        {
            var dataset = ReliabilityDataset.Load(name);
            var run = await ReliabilityRunner.RunAsync(dataset, mode.Value, label);
            var path = ReliabilityRunner.Save(run, ReliabilityRunner.RunFile(label, name, mode.Value));
            var c = Confusion.Of(run.Outcomes);
            Console.Error.WriteLine(string.Create(CultureInfo.InvariantCulture, $"[reliability] {label} {name} ({run.Mode}): TP {c.TruePositives} FN {c.FalseNegatives} FP {c.FalsePositives} TN {c.TrueNegatives} errors {c.Errors}; simulated provider responses {run.SimulatedProviderResponses}, network requests 0 -> {path}"));
        }

        Console.Error.WriteLine("[reliability] report written: " + WriteReport());
        return 0;
    }

    private static async Task<int> StressAsync(Dictionary<string, string> options)
    {
        int Option(string name, int fallback) =>
            options.TryGetValue(name, out var value) && int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed > 0 ? parsed : fallback;

        var fixtures = ReliabilityDataset.Load(ReliabilityDataset.HeldOut).Fixtures
            .Concat(ReliabilityDataset.Load(ReliabilityDataset.Tuning).Fixtures)
            .ToList();
        var result = await ReliabilityRunner.StressAsync(fixtures, Option("hosts", 4), Option("concurrency", 16), Option("rounds", 3), options.ContainsKey("burn") ? Option("burn", 0) : 0);
        var path = ReliabilityRunner.Save(result, result.BurnThreads == 0 ? "stress.json" : $"stress-burn{result.BurnThreads}.json");
        Console.Error.WriteLine(string.Create(CultureInfo.InvariantCulture, $"[reliability] stress: {result.Requests} requests, non-200 {result.NonSuccess}, server exceptions {result.ServerExceptions.Count}, decision mismatches {result.DecisionMismatches}, p50 {result.P50Ms} ms, p95 {result.P95Ms} ms, max {result.MaxMs} ms -> {path}"));
        return result.NonSuccess == 0 && result.DecisionMismatches == 0 ? 0 : 1;
    }

    private static string WriteReport()
    {
        Directory.CreateDirectory(ReliabilityRunner.ResultsDirectory);
        var path = Path.Combine(ReliabilityRunner.ResultsDirectory, ReliabilityReport.FileName);
        File.WriteAllText(path, ReliabilityReport.Build(), new UTF8Encoding(false));
        return path;
    }

    private static int Fail(string problem)
    {
        Console.Error.WriteLine("[reliability] " + problem);
        Console.Error.WriteLine("[reliability] " + Usage);
        return 2;
    }
}
