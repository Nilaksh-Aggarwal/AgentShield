using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AgentShield.Evaluation.Results;

/// <summary>
/// The results directory: <c>baseline.jsonl</c> (deterministic results, one per fixture), <c>attempts.jsonl</c> and
/// <c>sessions.jsonl</c> (append-only, one line per record, written as it happens so a stopped run can resume), and the
/// generated <c>report.md</c>.
/// </summary>
internal sealed class ResultStore
{
    public const string BaselineFile = "baseline.jsonl";
    public const string AttemptsFile = "attempts.jsonl";
    public const string SessionsFile = "sessions.jsonl";
    public const string ReportFile = "report.md";

    private static readonly UTF8Encoding NoBom = new(encoderShouldEmitUTF8Identifier: false);

    public ResultStore(string directory)
    {
        Directory = Path.GetFullPath(directory);
        System.IO.Directory.CreateDirectory(Directory);
    }

    public string Directory { get; }

    public IReadOnlyList<BaselineRecord> LoadBaseline() => Read<BaselineRecord>(BaselineFile);

    public IReadOnlyList<AttemptRecord> LoadAttempts() => Read<AttemptRecord>(AttemptsFile);

    public IReadOnlyList<SessionRecord> LoadSessions() => Read<SessionRecord>(SessionsFile);

    /// <summary>Replaces the baseline (callers only do this before any attempt exists, or with identical content).</summary>
    public void SaveBaseline(IEnumerable<BaselineRecord> records)
    {
        var path = Path.Combine(Directory, BaselineFile);
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, string.Concat(records.Select(record => EvaluationJson.Serialize(record) + "\n")), NoBom);
        File.Move(temporary, path, overwrite: true);
    }

    public void Append(AttemptRecord attempt) => AppendLine(AttemptsFile, EvaluationJson.Serialize(attempt));

    public void Append(SessionRecord session) => AppendLine(SessionsFile, EvaluationJson.Serialize(session));

    public void WriteReport(string markdown) => File.WriteAllText(Path.Combine(Directory, ReportFile), markdown, NoBom);

    /// <summary>Every file in the results directory (the artifacts the leak scan covers).</summary>
    public IReadOnlyList<string> ArtifactFiles() =>
        [.. System.IO.Directory.GetFiles(Directory, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal)];

    /// <summary>
    /// Deterministic results in a canonical form: fixture ID, decision and fused findings (code and severity), by ID. Two
    /// baselines with the same fingerprint come from detectors that behave identically on the set.
    /// </summary>
    public static string Fingerprint(IEnumerable<BaselineRecord> baseline)
    {
        var content = new StringBuilder();
        foreach (var record in baseline.OrderBy(record => record.FixtureId, StringComparer.Ordinal))
        {
            content.Append(record.FixtureId).Append('|').Append(record.ApiStatus).Append('|').Append(record.Decision).Append('|')
                .AppendJoin(',', record.Findings.Select(finding => finding.Code + ":" + finding.Severity)).Append('\n');
        }

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content.ToString())));
    }

    private void AppendLine(string file, string line)
    {
        // Appended and flushed per record: a run interrupted at any point keeps every attempt it made.
        using var stream = new FileStream(Path.Combine(Directory, file), FileMode.Append, FileAccess.Write, FileShare.Read);
        using var writer = new StreamWriter(stream, NoBom);
        writer.Write(line);
        writer.Write('\n');
    }

    private List<T> Read<T>(string file)
    {
        var path = Path.Combine(Directory, file);
        return File.Exists(path)
            ? [.. File.ReadAllLines(path, Encoding.UTF8).Where(line => line.Length > 0).Select(EvaluationJson.Deserialize<T>)]
            : [];
    }
}

internal static class EvaluationJson
{
    public static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

    public static string Serialize<T>(T value) => JsonSerializer.Serialize(value, Options);

    public static T Deserialize<T>(string json) =>
        JsonSerializer.Deserialize<T>(json, Options) ?? throw new InvalidOperationException("Empty result record.");
}
