using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace AgentShield.Evaluation.Reliability;

/// <summary>
/// <c>reliability</c>, <c>reliability-check</c>, <c>reliability-stress</c> and <c>reliability-report</c>: deterministic
/// and simulated-outage runs of the reliability sets, the check a new set must pass before it is pinned, a concurrency
/// check, and the comparison report. None of them can send a request to Google.
/// </summary>
internal static class ReliabilityCommand
{
    private const string Usage =
        "usage: reliability --label baseline|final [--split NAME|all] [--mode deterministic|ai-unavailable] | reliability-check --split NAME | reliability-stress [--hosts N] [--concurrency N] [--rounds N] [--burn N] | reliability-report";

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
            case "reliability-check":
                return Check(options);
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

        var available = ReliabilityDataset.Available();
        var split = options.GetValueOrDefault("split", "all");
        IReadOnlyList<string> splits = split == "all" ? available : [split];
        if (splits.Any(name => !available.Contains(name)))
        {
            return Fail("--split must be all or one of: " + string.Join(", ", available) + ".");
        }

        // A baseline is recorded once, before any rule change: it is never overwritten (a held-out set's baseline is
        // part of its evidence). Checked for every requested split before anything runs.
        var recorded = label == "baseline"
            ? splits.Where(name => File.Exists(Path.Combine(ReliabilityRunner.ResultsDirectory, ReliabilityRunner.RunFile(label, name, mode.Value)))).ToList()
            : [];
        if (recorded.Count > 0)
        {
            return Fail("A baseline is already recorded for " + string.Join(", ", recorded) + "; it is never overwritten. Use --label final, or move the file away deliberately.");
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

    /// <summary>
    /// Validates a set before it is pinned and measured (tests/Evaluation/reliability/README.md, "Adding a set"): format,
    /// labels, categories, secrets, IDs shared with other sets, and near duplicates between held-out and tuning data.
    /// Prints counts, fingerprints and fixture IDs only, never texts.
    /// </summary>
    private static int Check(Dictionary<string, string> options)
    {
        var available = ReliabilityDataset.Available();
        if (!options.TryGetValue("split", out var split) || split == ReliabilityDataset.Legacy || !available.Contains(split))
        {
            return Fail("--split must be one of: " + string.Join(", ", available.Where(name => name != ReliabilityDataset.Legacy)) + ".");
        }

        var dataset = ReliabilityDataset.Load(split);
        var problems = dataset.Problems(split).ToList();
        // A retired held-out split is development data: it is checked like a tuning split, and an active held-out split
        // is checked against it (ADR 0027).
        var heldOut = ReliabilityDataset.IsActiveHeldOut(split);
        var others = available.Where(name => name != split).Select(ReliabilityDataset.Load).ToList();
        foreach (var other in others)
        {
            var shared = dataset.Fixtures.Select(fixture => fixture.Id).Intersect(other.Fixtures.Select(fixture => fixture.Id), StringComparer.Ordinal).ToList();
            if (shared.Count > 0)
            {
                problems.Add($"IDs also used in {other.Split}: {string.Join(", ", shared.Take(10))}{(shared.Count > 10 ? ", …" : string.Empty)}.");
            }
        }

        // Development data must not contain a held-out input in other words: every active held-out split against every
        // tuning or retired split.
        var opposite = others.Where(other => other.Split != ReliabilityDataset.Legacy && ReliabilityDataset.IsActiveHeldOut(other.Split) != heldOut).ToList();
        foreach (var other in opposite)
        {
            var duplicates = heldOut ? ReliabilityDataset.NearDuplicates(dataset, other) : ReliabilityDataset.NearDuplicates(other, dataset);
            problems.AddRange(duplicates.Take(20).Select(pair => string.Create(CultureInfo.InvariantCulture, $"Near duplicate (held-out {pair.FirstId}, tuning {pair.SecondId}, similarity {pair.Similarity:0.00}).")));
        }

        var text = new StringBuilder();
        text.AppendLine(string.Create(CultureInfo.InvariantCulture, $"[reliability] {split}: {dataset.Name}, version {dataset.Version}, {(heldOut ? "HELD-OUT (pin before any rule change; never tune against it)" : "tuning (development data)")}"));
        text.AppendLine(string.Create(CultureInfo.InvariantCulture, $"[reliability] {dataset.Fixtures.Count} fixtures: {dataset.Fixtures.Count(f => f.Positive)} Block, {dataset.Fixtures.Count(f => !f.Positive)} Allow"));
        foreach (var group in dataset.Fixtures.GroupBy(fixture => fixture.Category, StringComparer.Ordinal).OrderBy(group => group.Key, StringComparer.Ordinal))
        {
            text.AppendLine(string.Create(CultureInfo.InvariantCulture, $"[reliability]   {group.Key}: {group.Count()}"));
        }

        text.AppendLine("[reliability] languages: " + string.Join(", ", dataset.Fixtures.GroupBy(fixture => fixture.Language ?? "(not recorded)", StringComparer.Ordinal).OrderBy(group => group.Key, StringComparer.Ordinal).Select(group => group.Key + " " + group.Count().ToString(CultureInfo.InvariantCulture))));
        text.AppendLine("[reliability] labelling: " + (dataset.Labelling.Length == 0 ? "(missing: state who wrote and labelled the set, and its source and licence)" : "recorded"));
        text.AppendLine("[reliability] content fingerprint: " + dataset.ContentFingerprint());
        text.AppendLine("[reliability] file SHA-256: " + Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(ReliabilityDataset.FileFor(split)))));
        foreach (var other in opposite)
        {
            var closest = heldOut ? ReliabilityDataset.ClosestPair(dataset, other) : ReliabilityDataset.ClosestPair(other, dataset);
            text.AppendLine(string.Create(CultureInfo.InvariantCulture, $"[reliability] closest pair with {other.Split}: {closest.FirstId} / {closest.SecondId}, similarity {closest.Similarity:0.00} (limit {ReliabilityDataset.NearDuplicateThreshold:0.00})"));
        }

        if (dataset.Labelling.Length == 0)
        {
            problems.Add("The \"labelling\" field is missing: state who wrote and labelled the set, and its source and licence.");
        }

        foreach (var problem in problems)
        {
            text.AppendLine("[reliability] PROBLEM: " + problem);
        }

        if (problems.Count == 0 && heldOut)
        {
            text.AppendLine(CultureInfo.InvariantCulture, $"[reliability] OK. Pin it in ReliabilitySetTests.PinnedHeldOut as [\"{split}\"] = \"{dataset.ContentFingerprint()}\", then record the baseline before changing any rule:");
            text.AppendLine(CultureInfo.InvariantCulture, $"[reliability]   dotnet run --project tests/AgentShield.Evaluation -- reliability --label baseline --split {split}");
        }
        else if (problems.Count == 0)
        {
            text.AppendLine("[reliability] OK.");
        }

        Console.Error.Write(text.ToString());
        return problems.Count == 0 ? 0 : 1;
    }

    private static async Task<int> StressAsync(Dictionary<string, string> options)
    {
        int Option(string name, int fallback) =>
            options.TryGetValue(name, out var value) && int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) && parsed > 0 ? parsed : fallback;

        var fixtures = ReliabilityDataset.Available()
            .Where(split => split != ReliabilityDataset.Legacy)
            .SelectMany(split => ReliabilityDataset.Load(split).Fixtures)
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
