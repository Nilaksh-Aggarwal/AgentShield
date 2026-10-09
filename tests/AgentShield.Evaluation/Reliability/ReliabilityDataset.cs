using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AgentShield.Evaluation.Dataset;
using AgentShield.Evaluation.Hosting;

namespace AgentShield.Evaluation.Reliability;

/// <summary>One labelled reliability input. Positive (an attack the firewall must not allow) unless labelled Allow.</summary>
internal sealed record ReliabilityFixture(string Id, string Category, string Label, string Source, string Text)
{
    public bool Positive => Label != Labels.Allow;
}

/// <summary>
/// A reliability set (tests/Evaluation/reliability): the tuning split, which detection rules may be developed against, or
/// the held-out split, which is written before any rule change and only measured. The legacy AI evaluation set is adapted
/// to the same shape so every set is measured the same way.
/// </summary>
internal sealed record ReliabilityDataset(string Name, string Split, int Version, IReadOnlyList<ReliabilityFixture> Fixtures)
{
    public const string HeldOut = "heldout";
    public const string Tuning = "tuning";
    public const string Legacy = "legacy-v1";

    public static readonly IReadOnlyList<string> AttackCategories =
    [
        "instruction-override", "role-change", "secret-extraction", "credential-theft", "tool-abuse", "context-poisoning",
        "encoded", "indirect",
    ];

    public static readonly IReadOnlyList<string> BenignCategories =
    [
        "benign-general", "benign-instruction-words", "benign-security-discussion", "benign-technical-content",
    ];

    public static string Directory => Path.Combine(Paths.Repository, "tests", "Evaluation", "reliability");

    public static string FileFor(string split) => Path.Combine(Directory, split + "-v1.json");

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
            fixture.GetProperty("text").GetString()!)).ToList();
        return new ReliabilityDataset(root.GetProperty("name").GetString()!, root.GetProperty("split").GetString()!, root.GetProperty("version").GetInt32(), fixtures);
    }

    /// <summary>SHA-256 over every fixture's ID, category, label, source and text: independent of file formatting.</summary>
    public string ContentFingerprint()
    {
        var canonical = new StringBuilder();
        foreach (var fixture in Fixtures)
        {
            canonical.Append(fixture.Id).Append('\u001f').Append(fixture.Category).Append('\u001f').Append(fixture.Label)
                .Append('\u001f').Append(fixture.Source).Append('\u001f').Append(fixture.Text).Append('\u001e');
        }

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(canonical.ToString())));
    }
}
