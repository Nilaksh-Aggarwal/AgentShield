using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AgentShield.Evaluation.Dataset;
using AgentShield.Evaluation.Hosting;

namespace AgentShield.Evaluation.Reliability;

/// <summary>One labelled reliability input. Positive (an attack the firewall must not allow) unless labelled Allow.</summary>
/// <param name="Language">ISO 639-1 code of the text's language; absent in the v1 sets (all English).</param>
internal sealed record ReliabilityFixture(string Id, string Category, string Label, string Source, string Text, string? Language = null)
{
    public bool Positive => Label != Labels.Allow;
}

/// <summary>A pair of inputs from two sets that share most of their words (token Jaccard above the threshold).</summary>
internal sealed record NearDuplicate(string FirstId, string SecondId, double Similarity);

/// <summary>
/// A reliability set (tests/Evaluation/reliability): a tuning split, which detection rules may be developed against, or
/// a held-out split, which is written and pinned before any rule change and only measured. The legacy AI evaluation set
/// is adapted to the same shape so every set is measured the same way.
/// </summary>
/// <remarks>
/// Splits are named by role and version. The v1 files keep their original names (<c>heldout</c> is
/// <c>heldout-v1.json</c>, <c>tuning</c> is <c>tuning-v1.json</c>); a later set is named after its file
/// (<c>heldout-v2.json</c> is the split <c>heldout-v2</c>), so adding a set never renames an earlier one or its results.
/// </remarks>
internal sealed partial record ReliabilityDataset(string Name, string Split, int Version, IReadOnlyList<ReliabilityFixture> Fixtures, string Labelling = "")
{
    public const string HeldOut = "heldout";
    public const string Tuning = "tuning";
    public const string Legacy = "legacy-v1";

    /// <summary>Inputs that share more of their words than this are near duplicates (development data would leak).</summary>
    public const double NearDuplicateThreshold = 0.5;

    public static readonly IReadOnlyList<string> AttackCategories =
    [
        "instruction-override", "role-change", "secret-extraction", "credential-theft", "tool-abuse", "context-poisoning",
        "encoded", "indirect",
    ];

    public static readonly IReadOnlyList<string> BenignCategories =
    [
        "benign-general", "benign-instruction-words", "benign-security-discussion", "benign-technical-content",
    ];

    public static readonly IReadOnlyList<string> Sources = ["user", "web", "email", "markdown", "api", "code", "ocr", "document"];

    /// <summary>The API's input limit (<c>AnalyzeInputRequest.MaxInputLength</c>): a longer input could not be measured.</summary>
    public const int MaxTextLength = 32_000;

    public static string Directory => Path.Combine(Paths.Repository, "tests", "Evaluation", "reliability");

    /// <summary>Every reliability set on disk, held-out splits first, then tuning splits, then the legacy set.</summary>
    public static IReadOnlyList<string> Available()
    {
        var splits = System.IO.Directory.GetFiles(Directory, "*.json")
            .Select(Path.GetFileNameWithoutExtension)
            .Select(name => FileName().Match(name!))
            .Where(match => match.Success)
            .Select(match => (Role: match.Groups["role"].Value, Version: int.Parse(match.Groups["version"].Value, System.Globalization.CultureInfo.InvariantCulture)))
            .OrderBy(set => set.Role == HeldOut ? 0 : 1)
            .ThenBy(set => set.Version)
            .Select(set => set.Version == 1 ? set.Role : set.Role + "-v" + set.Version.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return [.. splits, Legacy];
    }

    /// <summary>
    /// Held-out splits the owner retired to development data, with the date (ADR 0027). A retired split stays pinned and
    /// unedited; its held-out evidence is the results frozen before retirement (<c>results/frozen-&lt;split&gt;-v1</c> for
    /// v1), and everything measured on it afterwards is a development number.
    /// </summary>
    public static readonly IReadOnlyDictionary<string, DateTimeOffset> Retired = new Dictionary<string, DateTimeOffset>(StringComparer.Ordinal)
    {
        // Frozen at 06:20:35 UTC, after its last real-Gemini session (06:11:20 UTC); its tool-abuse misses were then
        // studied to extend IO-006.
        [HeldOut] = new DateTimeOffset(2026, 10, 9, 6, 20, 35, TimeSpan.Zero),
    };

    /// <summary>A held-out split that is not retired: the only kind whose results are held-out evidence.</summary>
    public static bool IsActiveHeldOut(string split) => IsHeldOut(split) && !Retired.ContainsKey(split);

    /// <summary>
    /// Development data: a tuning split or a retired held-out split. An active held-out split must not share an input or a
    /// near duplicate with any of them.
    /// </summary>
    public static bool IsDevelopmentData(string split) => split != Legacy && !IsActiveHeldOut(split);

    /// <summary>Where the results of a retired held-out split were frozen before it was retired.</summary>
    public static string FrozenEvidenceDirectory(string split) =>
        Path.Combine(Directory, "results", "frozen-" + (split is HeldOut ? "heldout-v1" : split));

    /// <summary>True for every held-out split (<c>heldout</c>, <c>heldout-v2</c>, …): pinned, only ever measured.</summary>
    public static bool IsHeldOut(string split) => split == HeldOut || (SplitName().IsMatch(split) && split.StartsWith(HeldOut + "-v", StringComparison.Ordinal));

    public static string FileFor(string split)
    {
        if (!SplitName().IsMatch(split))
        {
            throw new ArgumentException("Unknown reliability split name.", nameof(split));
        }

        return Path.Combine(Directory, (split is HeldOut or Tuning ? split + "-v1" : split) + ".json");
    }

    public static ReliabilityDataset Load(string split)
    {
        if (split == Legacy)
        {
            var legacy = EvaluationDataset.Load(Paths.DatasetFile);
            return new ReliabilityDataset(
                "AI security evaluation set (v1, 2026-09-30)",
                Legacy,
                legacy.Version,
                [.. legacy.Fixtures.Select(fixture => new ReliabilityFixture(fixture.Id, fixture.Category + " " + fixture.CategoryName, fixture.Label, "user", fixture.Text))]);
        }

        using var document = JsonDocument.Parse(File.ReadAllText(FileFor(split)));
        var root = document.RootElement;
        var fixtures = root.GetProperty("fixtures").EnumerateArray().Select(fixture => new ReliabilityFixture(
            fixture.GetProperty("id").GetString()!,
            fixture.GetProperty("category").GetString()!,
            fixture.GetProperty("label").GetString()!,
            fixture.GetProperty("source").GetString()!,
            fixture.GetProperty("text").GetString()!,
            fixture.TryGetProperty("language", out var language) ? language.GetString() : null)).ToList();
        return new ReliabilityDataset(
            root.GetProperty("name").GetString()!,
            root.GetProperty("split").GetString()!,
            root.GetProperty("version").GetInt32(),
            fixtures,
            root.TryGetProperty("labelling", out var labelling) ? labelling.GetString() ?? string.Empty : string.Empty);
    }

    /// <summary>
    /// SHA-256 over every fixture's ID, category, label, source and text (and language, when the set records one):
    /// independent of file formatting. Sets without languages (v1) keep the fingerprint they were pinned with.
    /// </summary>
    public string ContentFingerprint()
    {
        var canonical = new StringBuilder();
        foreach (var fixture in Fixtures)
        {
            canonical.Append(fixture.Id).Append('\u001f').Append(fixture.Category).Append('\u001f').Append(fixture.Label)
                .Append('\u001f').Append(fixture.Source).Append('\u001f').Append(fixture.Text);
            if (fixture.Language is not null)
            {
                canonical.Append('\u001f').Append(fixture.Language);
            }

            canonical.Append('\u001e');
        }

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString())));
    }

    /// <summary>
    /// What makes a reliability set unusable as evidence: the split name, IDs, labels, categories, sources, languages,
    /// text lengths, and anything that looks like a real secret. Problems name fixture IDs only, never texts.
    /// </summary>
    public IReadOnlyList<string> Problems(string expectedSplit)
    {
        var problems = new List<string>();
        if (Split != expectedSplit)
        {
            problems.Add($"The file's \"split\" is {Split}, but it was loaded as {expectedSplit}.");
        }

        if (Fixtures.Count == 0)
        {
            problems.Add("The set has no fixtures.");
        }

        problems.AddRange(Fixtures.GroupBy(fixture => fixture.Id, StringComparer.Ordinal).Where(group => group.Count() > 1).Select(group => $"Duplicate ID {group.Key}."));
        foreach (var fixture in Fixtures)
        {
            var categories = fixture.Label switch
            {
                Labels.Block => AttackCategories,
                Labels.Allow => BenignCategories,
                _ => null,
            };
            if (categories is null)
            {
                problems.Add($"{fixture.Id}: the label must be Block or Allow.");
            }
            else if (!categories.Contains(fixture.Category))
            {
                problems.Add($"{fixture.Id}: category {fixture.Category} is not a {(fixture.Positive ? "attack" : "benign")} category.");
            }

            if (!Sources.Contains(fixture.Source))
            {
                problems.Add($"{fixture.Id}: unknown source.");
            }

            if (fixture.Language is { } language && !LanguageCode().IsMatch(language))
            {
                problems.Add($"{fixture.Id}: the language must be an ISO 639-1 code.");
            }

            if (fixture.Text.Trim().Length == 0 || fixture.Text.Length > MaxTextLength)
            {
                problems.Add($"{fixture.Id}: the text must have 1 to {MaxTextLength} characters.");
            }

            if (SecretLike().IsMatch(fixture.Text))
            {
                problems.Add($"{fixture.Id}: the text contains something that looks like a real secret.");
            }
        }

        return problems;
    }

    /// <summary>Pairs of inputs from <paramref name="first"/> and <paramref name="second"/> that are near duplicates.</summary>
    public static IReadOnlyList<NearDuplicate> NearDuplicates(ReliabilityDataset first, ReliabilityDataset second)
    {
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(second);

        var secondWords = second.Fixtures.Select(fixture => (fixture.Id, Words: Words(fixture.Text))).ToList();
        return
        [
            .. first.Fixtures
                .SelectMany(held => secondWords.Select(tuned => new NearDuplicate(held.Id, tuned.Id, Jaccard(Words(held.Text), tuned.Words))))
                .Where(pair => pair.Similarity > NearDuplicateThreshold)
                .OrderByDescending(pair => pair.Similarity),
        ];
    }

    /// <summary>The highest token similarity between any input of <paramref name="first"/> and any of <paramref name="second"/>.</summary>
    public static NearDuplicate ClosestPair(ReliabilityDataset first, ReliabilityDataset second)
    {
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(second);

        var secondWords = second.Fixtures.Select(fixture => (fixture.Id, Words: Words(fixture.Text))).ToList();
        return first.Fixtures
            .SelectMany(held => secondWords.Select(tuned => new NearDuplicate(held.Id, tuned.Id, Jaccard(Words(held.Text), tuned.Words))))
            .MaxBy(pair => pair.Similarity)!;
    }

    /// <summary>
    /// The set in the AI evaluation runner's shape, so a held-out split can be run against the real provider with the
    /// runner's safeguards (ADR 0017). It carries no expectations, tags or rationales: only IDs, labels and texts.
    /// </summary>
    public EvaluationDataset ToEvaluationDataset() => new(
        Version,
        Fixtures.Select(fixture => fixture.Category).Distinct(StringComparer.Ordinal).ToDictionary(category => category, category => category, StringComparer.Ordinal),
        [
            .. Fixtures.Select(fixture => new Fixture(
                fixture.Id, fixture.Category, fixture.Category, fixture.Label, fixture.Language ?? "en", "none",
                ExpectDeterministic: false, ExpectAiFinding: fixture.Positive, ExpectedCategories: [], Tags: [], ReviewFlags: [],
                Rationale: "(no rationale recorded in reliability sets)", fixture.Text, Revealed: null)),
        ]);

    private static HashSet<string> Words(string text) =>
        [.. WordPattern().Matches(text.ToLowerInvariant()).Select(match => match.Value).Where(word => word.Length > 2)];

    private static double Jaccard(HashSet<string> a, HashSet<string> b)
    {
        var shared = a.Count(b.Contains);
        var union = a.Count + b.Count - shared;
        return union == 0 ? 0 : (double)shared / union;
    }

    [GeneratedRegex(@"^(?<role>heldout|tuning)-v(?<version>[1-9][0-9]{0,2})$")]
    private static partial Regex FileName();

    [GeneratedRegex(@"^(?:heldout|tuning)(?:-v(?:[2-9]|[1-9][0-9]{1,2}))?$")]
    private static partial Regex SplitName();

    [GeneratedRegex("^[a-z]{2}$")]
    private static partial Regex LanguageCode();

    [GeneratedRegex(@"\p{L}[\p{L}\p{N}]*|[0-9]+")]
    private static partial Regex WordPattern();

    [GeneratedRegex(@"AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|-----BEGIN [A-Z ]*PRIVATE KEY|sk-[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")]
    private static partial Regex SecretLike();
}
