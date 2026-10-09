using System.Globalization;
using AgentShield.Evaluation.Dataset;
using AgentShield.Evaluation.Hosting;
using AgentShield.Evaluation.Report;
using AgentShield.Evaluation.Results;
using AgentShield.Evaluation.Run;
using AgentShield.Evaluation.Safety;

namespace AgentShield.Evaluation;

/// <summary>
/// AgentShield AI security evaluation runner (ADR 0017). Run from the repository root:
/// <code>
/// dotnet run --project tests/AgentShield.Evaluation -- plan     [options]   # pre-flight only; no AI request
/// dotnet run --project tests/AgentShield.Evaluation -- final    [options]   # REAL Gemini: spends free-tier quota
/// dotnet run --project tests/AgentShield.Evaluation -- simulate [options] --results DIR   # local fake provider
/// dotnet run --project tests/AgentShield.Evaluation -- baseline [--results DIR]
/// dotnet run --project tests/AgentShield.Evaluation -- report   [--results DIR]
/// dotnet run --project tests/AgentShield.Evaluation -- scan FILE...
/// </code>
/// Options: <c>--max-calls N</c> (hard cap), <c>--spacing-seconds S</c> (default 20, at least 15 for real runs),
/// <c>--provider-rpm N</c> and <c>--provider-rpd-remaining N</c> (as AI Studio shows them today; required for real
/// runs), <c>--subset all|attacks|benign</c>, <c>--exclude-failed</c>, <c>--results DIR</c> (default
/// tests/Evaluation/results).
/// </summary>
internal static class EvaluationProgram
{
    public static async Task<int> Main(string[] args)
    {
        var options = CommandLine.Parse(args, Paths.DefaultResults);
        if (options.Problems.Count > 0)
        {
            foreach (var problem in options.Problems)
            {
                Console.Error.WriteLine("[eval] " + problem);
            }

            Console.Error.WriteLine("[eval] " + CommandLine.Usage);
            return SessionResult.RefusedBeforeSending;
        }

        var dataset = EvaluationDataset.Load(Paths.DatasetFile);
        switch (options.Command)
        {
            case "scan":
                var findings = LeakCheck.ForDataset(dataset).ScanFiles(options.Files);
                foreach (var (file, labels) in findings)
                {
                    Console.Error.WriteLine("[eval] " + file + ": " + (labels.Count == 0 ? "clean" : "HITS " + string.Join(", ", labels)));
                }

                return findings.Any(result => result.Labels.Count > 0) ? 1 : 0;

            case "report":
                var reportStore = new ResultStore(options.Results);
                reportStore.WriteReport(ReportBuilder.Build(dataset, reportStore.LoadBaseline(), reportStore.LoadAttempts(), reportStore.LoadSessions()));
                Console.Error.WriteLine("[eval] report written: " + Path.Combine(reportStore.Directory, ResultStore.ReportFile));
                return 0;

            case "baseline":
                return await BaselineAsync(dataset, new ResultStore(options.Results));

            default:
                var store = new ResultStore(options.Results);
                var logDirectory = Path.Combine(Path.GetTempPath(), "agentshield-ai-evaluation", "logs", DateTimeOffset.UtcNow.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture));
                var session = options.Command == "simulate" ? Simulated(options, logDirectory) : Real(options, logDirectory);
                var result = await SessionRunner.RunAsync(dataset, store, session);
                return result.ExitCode;
        }
    }

    private static SessionOptions Real(CommandLine options, string logDirectory) => new()
    {
        Mode = RunMode.Real,
        PlanOnly = options.Command == "plan",
        Subset = options.Subset,
        MaxCalls = options.MaxCalls,
        SpacingSeconds = options.SpacingSeconds,
        ProviderRpm = options.ProviderRpm,
        ProviderRpdRemaining = options.ProviderRpdRemaining,
        ExcludeFailed = options.ExcludeFailed,
        LogDirectory = logDirectory,
    };

    private static SessionOptions Simulated(CommandLine options, string logDirectory)
    {
        var clock = new VirtualClock();
        return new SessionOptions
        {
            Mode = RunMode.Simulated,
            Subset = options.Subset,
            MaxCalls = options.MaxCalls,
            SpacingSeconds = options.SpacingSeconds,
            ExcludeFailed = options.ExcludeFailed,
            LogDirectory = logDirectory,
            FakeTransport = SimulatedGemini.Transport,
            Settings = [new("Ai:Gemini:ApiKey", "simulated-key-not-real-0000")],
            Clock = clock,
            Delay = (wait, _) =>
            {
                clock.Advance(wait);
                return Task.CompletedTask;
            },
        };
    }

    private static async Task<int> BaselineAsync(EvaluationDataset dataset, ResultStore store)
    {
        var run = await BaselineRunner.RunAsync(dataset);
        if (run.Problems.Count > 0)
        {
            run.Problems.ToList().ForEach(problem => Console.Error.WriteLine("[eval] " + problem));
            return SessionResult.RefusedBeforeSending;
        }

        var stored = store.LoadBaseline();
        if (stored.Count > 0 && ResultStore.Fingerprint(stored) != ResultStore.Fingerprint(run.Records) && store.LoadAttempts().Count > 0)
        {
            Console.Error.WriteLine("[eval] REFUSED: the deterministic results differ from the stored baseline and attempts exist (detectors changed).");
            return SessionResult.RefusedBeforeSending;
        }

        store.SaveBaseline(run.Records);
        store.WriteReport(ReportBuilder.Build(dataset, store.LoadBaseline(), store.LoadAttempts(), store.LoadSessions()));
        Console.Error.WriteLine(string.Create(CultureInfo.InvariantCulture, $"[eval] baseline: {run.Records.Count} fixtures, Block {run.Records.Count(r => r.Decision == Labels.Block)}, Review {run.Records.Count(r => r.Decision == Labels.Review)}, Allow {run.Records.Count(r => r.Decision == Labels.Allow)}; zero provider requests. Stored in {store.Directory}"));
        return 0;
    }
}

/// <summary>Command-line options with the safety checks a real run needs before anything starts.</summary>
internal sealed record CommandLine(
    string Command,
    string Results,
    Subset Subset,
    int MaxCalls,
    int SpacingSeconds,
    int? ProviderRpm,
    int? ProviderRpdRemaining,
    bool ExcludeFailed,
    IReadOnlyList<string> Files,
    IReadOnlyList<string> Problems)
{
    public const string Usage =
        "usage: plan|final|simulate|baseline|report|scan [--max-calls N] [--spacing-seconds S] [--provider-rpm N] [--provider-rpd-remaining N] [--subset all|attacks|benign] [--exclude-failed] [--results DIR] [FILE...]";

    private static readonly string[] Commands = ["plan", "final", "simulate", "baseline", "report", "scan"];

    public static CommandLine Parse(string[] args, string defaultResults)
    {
        ArgumentNullException.ThrowIfNull(args);

        var problems = new List<string>();
        var command = args.Length > 0 && Commands.Contains(args[0]) ? args[0] : string.Empty;
        if (command.Length == 0)
        {
            problems.Add("Unknown or missing command.");
        }

        var results = defaultResults;
        var subset = Subset.All;
        int maxCalls = 0, spacing = 20;
        int? rpm = null, rpd = null;
        var excludeFailed = false;
        var files = new List<string>();
        for (var i = 1; i < args.Length; i++)
        {
            string? Next() => i + 1 < args.Length ? args[++i] : null;
            int? Number()
            {
                var value = Next();
                if (int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var number))
                {
                    return number;
                }

                problems.Add(args[i - 1] + " needs a whole number.");
                return null;
            }

            switch (args[i])
            {
                case "--results":
                    results = Next() is { } directory ? Path.GetFullPath(directory) : results;
                    break;
                case "--max-calls":
                    maxCalls = Number() ?? 0;
                    break;
                case "--spacing-seconds":
                    spacing = Number() ?? spacing;
                    break;
                case "--provider-rpm":
                    rpm = Number();
                    break;
                case "--provider-rpd-remaining":
                    rpd = Number();
                    break;
                case "--exclude-failed":
                    excludeFailed = true;
                    break;
                case "--subset":
                    var value = Next();
                    if (!Enum.TryParse(value, ignoreCase: true, out subset) || !Enum.IsDefined(subset) || int.TryParse(value, CultureInfo.InvariantCulture, out _))
                    {
                        problems.Add("--subset must be all, attacks or benign.");
                    }

                    break;
                default:
                    if (command == "scan" && !args[i].StartsWith("--", StringComparison.Ordinal))
                    {
                        files.Add(Path.GetFullPath(args[i]));
                    }
                    else
                    {
                        problems.Add("Unknown option " + args[i] + ".");
                    }

                    break;
            }
        }

        var usesRealResults = string.Equals(
            Path.GetFullPath(results).TrimEnd(Path.DirectorySeparatorChar),
            Path.GetFullPath(defaultResults).TrimEnd(Path.DirectorySeparatorChar),
            StringComparison.OrdinalIgnoreCase);

        if (command is "plan" or "final")
        {
            problems.AddRange(SafetyLimits.Check(maxCalls, spacing, rpm, rpd));

            // Completed fixtures are skipped only because their results are in the real store; another directory starts
            // empty and would send every fixture to the provider again.
            if (!usesRealResults)
            {
                problems.Add("A real run reads and writes only the real results directory, where completed fixtures are never sent again. To start a separate evaluation, move the existing results away first.");
            }
        }

        if (command == "simulate")
        {
            if (maxCalls < 1)
            {
                problems.Add("--max-calls is required.");
            }

            if (usesRealResults)
            {
                problems.Add("A simulation must write to its own --results directory, never to the real results.");
            }
        }

        if (command == "scan" && files.Count == 0)
        {
            problems.Add("scan needs at least one file.");
        }

        return new CommandLine(command, results, subset, maxCalls, spacing, rpm, rpd, excludeFailed, files, problems);
    }
}
