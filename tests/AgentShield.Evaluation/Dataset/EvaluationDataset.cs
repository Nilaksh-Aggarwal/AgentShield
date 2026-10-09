using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace AgentShield.Evaluation.Dataset;

/// <summary>Expected decisions a fixture can be labelled with.</summary>
internal static class Labels
{
    public const string Allow = "Allow";
    public const string Review = "Review";
    public const string Block = "Block";

    public static readonly IReadOnlyList<string> All = [Allow, Review, Block];
}

/// <summary>One labelled, synthetic input (tests/Evaluation/README.md describes every field).</summary>
internal sealed record Fixture(
    string Id,
    string Category,
    string CategoryName,
    string Label,
    string Language,
    string Obfuscation,
    bool ExpectDeterministic,
    bool ExpectAiFinding,
    IReadOnlyList<string> ExpectedCategories,
    IReadOnlyList<string> Tags,
    IReadOnlyList<string> ReviewFlags,
    string Rationale,
    string Text,
    string? Revealed)
{
    /// <summary>The firewall must not allow it (labelled Block or Review).</summary>
    public bool Positive => Label != Labels.Allow;

    /// <summary>
    /// Categories A–I hold attacks (and ambiguous requests); J–P benign content. A reliability set adapted to this shape
    /// names its categories in words and keeps attacks and benign inputs in separate categories, so its label decides.
    /// </summary>
    public bool InAttackCategory => Category.Length == 1 ? string.CompareOrdinal(Category, "I") <= 0 : Positive;
}

/// <summary>Breakdowns used by the report. Attack tags follow fixed rules; benign tags are assigned per fixture.</summary>
internal static class Taxonomy
{
    public static readonly IReadOnlyList<(string Tag, string Name)> AttackTags =
    [
        ("instruction-override", "Instruction override"),
        ("role-manipulation", "Role manipulation"),
        ("secret-extraction", "Secret extraction"),
        ("obfuscation", "Obfuscation"),
        ("multilingual", "Multilingual"),
        ("paraphrased", "Paraphrased"),
        ("exfiltration", "Credential/data exfiltration"),
        ("multi-step", "Multi-step"),
    ];

    public static readonly IReadOnlyList<(string Tag, string Name)> BenignTags =
    [
        ("technical-documentation", "Technical documentation"),
        ("security-education", "Security education"),
        ("prompt-injection-explanation", "Prompt-injection explanations"),
        ("auth-examples", "Authentication/JWT/API-key examples"),
        ("database-examples", "SQL/database examples"),
        ("cloud-container-examples", "Docker/cloud examples"),
        ("quoted-instructions", "Quoted instructions"),
        ("benign-edge-case", "Other benign edge cases"),
    ];

    public static readonly IReadOnlyList<(string Flag, string Name)> ReviewFlags =
    [
        ("ai-expectation-debatable", "Expected AI behaviour is debatable"),
        ("label-interpretation", "Label depends on interpretation"),
    ];

    public static readonly IReadOnlyList<string> AttackCategories = ["InstructionOverride", "RoleManipulation", "SecretExtraction", "Obfuscation"];

    public static readonly IReadOnlyList<string> Obfuscations = ["none", "base64", "leetspeak", "homoglyph", "spacing", "zero-width", "rot13", "reversed", "split", "hex"];
}

internal sealed record EvaluationDataset(int Version, IReadOnlyDictionary<string, string> Categories, IReadOnlyList<Fixture> Fixtures)
{
    private static readonly JsonSerializerOptions Options = new(JsonSerializerDefaults.Web);

    public static EvaluationDataset Load(string path)
    {
        using var stream = File.OpenRead(path);
        var dataset = JsonSerializer.Deserialize<EvaluationDataset>(stream, Options)
            ?? throw new InvalidOperationException("The evaluation set is empty.");
        return dataset with
        {
            Fixtures = [.. dataset.Fixtures.Select(fixture => fixture with { Tags = fixture.Tags ?? [], ReviewFlags = fixture.ReviewFlags ?? [] })],
        };
    }

    public Fixture Get(string id) => Fixtures.First(fixture => fixture.Id == id);

    /// <summary>
    /// SHA-256 over what is sent (fixture ID and text), in file order. Stored attempts can be combined only while it is
    /// unchanged: an attempt observes how the pipeline treats a text, so a label change (scoring) does not invalidate it,
    /// but any change to a text does.
    /// </summary>
    public string InputFingerprint()
    {
        var content = new StringBuilder();
        foreach (var fixture in Fixtures)
        {
            content.Append(fixture.Id).Append('\u001f').Append(fixture.Text).Append('\u001e');
        }

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content.ToString())));
    }

    /// <summary>
    /// SHA-256 over every field that decides what is sent and how it is scored (all v1 fields: ID, category, label,
    /// language, obfuscation, expectations, rationale, text, hidden text), in file order. Tags and review flags are
    /// reporting metadata and are left out, so adding them never invalidates stored results.
    /// </summary>
    public string ContentFingerprint()
    {
        var content = new StringBuilder();
        foreach (var fixture in Fixtures)
        {
            string[] fields =
            [
                fixture.Id, fixture.Category, fixture.CategoryName, fixture.Label, fixture.Language, fixture.Obfuscation,
                fixture.ExpectDeterministic ? "true" : "false", fixture.ExpectAiFinding ? "true" : "false",
                string.Join(',', fixture.ExpectedCategories), fixture.Rationale, fixture.Text, fixture.Revealed ?? string.Empty,
            ];
            content.Append(string.Join('\u001f', fields)).Append('\u001e');
        }

        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(content.ToString())));
    }
}
