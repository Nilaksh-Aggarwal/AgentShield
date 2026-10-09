using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.RegularExpressions;
using AgentShield.Evaluation.Dataset;
using AgentShield.Evaluation.Hosting;
using AgentShield.Evaluation.Results;

namespace AgentShield.Evaluation.Safety;

/// <summary>
/// Looks for forbidden values in texts: exactly (raw and JSON-escaped) and, for prose, any run of six words, so a partial
/// copy is found too. Reports labels and counts, never values.
/// </summary>
internal sealed partial class LeakCheck
{
    private const int ShingleWords = 6;
    private static readonly JsonSerializerOptions Relaxed = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    private readonly List<(string Label, string[] Variants, HashSet<string> Shingles)> _forbidden = [];

    public int Count => _forbidden.Count;

    /// <summary>Everything the evaluation set and the code make forbidden: inputs, hidden payloads, keys, the prompt.</summary>
    public static LeakCheck ForDataset(EvaluationDataset dataset)
    {
        ArgumentNullException.ThrowIfNull(dataset);

        var check = new LeakCheck();
        foreach (var fixture in dataset.Fixtures)
        {
            check.Add("input:" + fixture.Id, fixture.Text);
            check.Add("decoded-payload:" + fixture.Id, fixture.Revealed);
        }

        check.Add("development-api-key", EvaluationHost.DevelopmentKey, shingles: false);
        var instruction = EvaluationHost.SystemInstruction();
        check.Add("prompt:system-instruction", instruction);
        var line = 0;
        foreach (var text in instruction.Split('\n').Select(part => part.Trim()).Where(part => part.Length >= 30))
        {
            check.Add(string.Create(CultureInfo.InvariantCulture, $"prompt:line-{++line}"), text, shingles: false);
        }

        check.Add("prompt:user-turn-field", "\"deterministicFindings\"", shingles: false);
        return check;
    }

    /// <param name="label">What the value is (reported instead of the value).</param>
    /// <param name="value">The forbidden value; ignored when shorter than 8 characters.</param>
    /// <param name="shingles">Also match any six-word run (prose); off for keys and JSON structure.</param>
    public void Add(string label, string? value, bool shingles = true)
    {
        if (string.IsNullOrEmpty(value) || value.Length < 8)
        {
            return;
        }

        string[] variants = [.. new[] { value, JsonEncodedText.Encode(value).ToString(), JsonSerializer.Serialize(value, Relaxed).Trim('"') }.Distinct(StringComparer.Ordinal)];
        _forbidden.Add((label, variants, shingles ? Shingles(value) : []));
    }

    public List<LeakResult> Run(IReadOnlyDictionary<string, IReadOnlyList<string>> targets)
    {
        ArgumentNullException.ThrowIfNull(targets);

        var targetShingles = targets.ToDictionary(target => target.Key, target => target.Value.Select(Shingles).ToList(), StringComparer.Ordinal);
        var results = new List<LeakResult>();
        foreach (var (label, variants, shingles) in _forbidden)
        {
            var hits = new SortedDictionary<string, int>(StringComparer.Ordinal);
            foreach (var (name, texts) in targets)
            {
                var count = 0;
                for (var i = 0; i < texts.Count; i++)
                {
                    var exact = Array.Exists(variants, variant => texts[i].Contains(variant, StringComparison.Ordinal));
                    if (exact || (shingles.Count > 0 && targetShingles[name][i].Overlaps(shingles)))
                    {
                        count++;
                    }
                }

                if (count > 0)
                {
                    hits[name] = count;
                }
            }

            if (hits.Count > 0)
            {
                results.Add(new LeakResult(label, hits));
            }
        }

        return results;
    }

    /// <summary>Leak scan of files (evaluation artifacts, reports, docs); also flags anything shaped like a Google API key.</summary>
    public IReadOnlyList<(string File, IReadOnlyList<string> Labels)> ScanFiles(IEnumerable<string> files)
    {
        ArgumentNullException.ThrowIfNull(files);

        var results = new List<(string, IReadOnlyList<string>)>();
        foreach (var file in files)
        {
            var text = File.ReadAllText(file);
            var labels = Run(new Dictionary<string, IReadOnlyList<string>>(StringComparer.Ordinal) { ["file"] = [text] })
                .Select(leak => leak.Label).ToList();
            if (GoogleApiKey().IsMatch(text))
            {
                labels.Add("google-api-key-format");
            }

            results.Add((file, labels));
        }

        return results;
    }

    public static HashSet<string> Shingles(string text)
    {
        var words = WordSeparators().Split(text.ToLowerInvariant()).Where(word => word.Length > 0).ToArray();
        var set = new HashSet<string>(StringComparer.Ordinal);
        for (var i = 0; i + ShingleWords <= words.Length; i++)
        {
            set.Add(string.Join(' ', words, i, ShingleWords));
        }

        return set;
    }

    [GeneratedRegex(@"[\s""'`,.;:!?(){}\[\]<>|\\/]+")]
    private static partial Regex WordSeparators();

    [GeneratedRegex("AIza[0-9A-Za-z_-]{35}")]
    private static partial Regex GoogleApiKey();
}
