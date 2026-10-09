using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using AgentShield.Evaluation.Dataset;
using AgentShield.IntegrationTests.AiAnalysis;
using AgentShield.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Serilog.Events;
using static AgentShield.IntegrationTests.AiAnalysis.FakeGeminiApi;

namespace AgentShield.IntegrationTests.Evaluation;

/// <summary>
/// The Milestone 7 evaluation set (<c>tests/Evaluation</c>): it is well-formed and synthetic, and for every fixture the AI
/// stage can only add findings, whatever the provider answers or however it fails. Real composition, real Gemini adapter,
/// fake Gemini transport, manual clock. No request reaches Google.
/// </summary>
/// <remarks>
/// The real-Gemini measurement is the manual runner <c>tests/AgentShield.Evaluation</c>; these tests hold the
/// decision-integrity properties it reports for every fixture, without quota.
/// </remarks>
public class AiEvaluationSetTests(AgentShieldFactory factory) : IClassFixture<AgentShieldFactory>
{
    private const string Route = "/api/v1/firewall/analyze";
    private const string GeminiKey = "zq7key-AIzaEvaluationTestsOnly012345";
    private const string DevelopmentKey = "agentshield-development-only-key-not-a-secret";
    private const string Incomplete = "InconclusiveAnalysis.AiAnalysisIncomplete";
    private const string DescriptionMarker = "model-written-text-7f3a91";

    private static readonly string[] AttackCategories = ["InstructionOverride", "RoleManipulation", "SecretExtraction", "Obfuscation"];
    private static readonly string[] Obfuscations = ["none", "base64", "leetspeak", "homoglyph", "spacing", "zero-width", "rot13", "reversed", "split", "hex"];

    /// <summary>Raised AI budgets (test host only), so every fixture the deterministic rules do not block is admitted.</summary>
    private static readonly (string Key, string Value)[] UnboundedCapacity =
    [
        ("Ai:Capacity:GlobalRequestsPerMinute", "1000"),
        ("Ai:Capacity:GlobalRequestsPerDay", "1000"),
        ("Ai:Capacity:GlobalInputTokensPerMinute", "10000000"),
        ("Ai:Capacity:DefaultClient:MaxPerMinute", "1000"),
        ("Ai:Capacity:DefaultClient:MaxPerDay", "1000"),
        ("Ai:Capacity:DefaultClient:MaxInputTokensPerMinute", "10000000"),
    ];

    /// <summary>Content fingerprint of dataset v1 (2026-09-30). Texts, labels and expectations must never change silently.</summary>
    private const string V1ContentFingerprint = "639f8b267569f7288e99f53aa5ecc7253e2224268dc4068f5dcc18faf0cc5d54";

    private static readonly Lazy<EvaluationDataset> Set = new(() => EvaluationDataset.Load(Path.Combine(AppContext.BaseDirectory, "Evaluation", "ai-security-evaluation-set.json")));

    // ── The set itself ──────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void EvaluationSet_IsWellFormed_AndEveryFixtureIsLabelled()
    {
        var set = Set.Value;
        var problems = new List<string>();

        Assert.Equal(16, set.Categories.Count);
        foreach (var group in set.Fixtures.GroupBy(fixture => fixture.Category))
        {
            if (group.Count() < 5)
            {
                problems.Add($"category {group.Key}: fewer than 5 fixtures");
            }
        }

        Assert.Equal(set.Categories.Keys.Order(StringComparer.Ordinal), set.Fixtures.Select(fixture => fixture.Category).Distinct().Order(StringComparer.Ordinal));
        Assert.Equal(set.Fixtures.Count, set.Fixtures.Select(fixture => fixture.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(set.Fixtures.Count, set.Fixtures.Select(fixture => fixture.Text).Distinct(StringComparer.Ordinal).Count());

        foreach (var fixture in set.Fixtures)
        {
            var attackCategory = string.CompareOrdinal(fixture.Category, "I") <= 0;
            var checks = new (bool Ok, string Rule)[]
            {
                (Regex.IsMatch(fixture.Id, "^[A-P][0-9]{2}$") && fixture.Id[..1] == fixture.Category, "id"),
                (set.Categories.TryGetValue(fixture.Category, out var name) && name == fixture.CategoryName, "category name"),
                (fixture.Label is "Allow" or "Review" or "Block", "label"),
                (attackCategory ? fixture.Label != "Allow" : fixture.Label != "Block", "label fits the category"),
                (fixture.Text.Trim().Length > 0 && fixture.Text.Length <= 32_000, "text"),
                (!string.IsNullOrWhiteSpace(fixture.Rationale), "rationale"),
                (Regex.IsMatch(fixture.Language, "^[a-z]{2}$"), "language"),
                (Obfuscations.Contains(fixture.Obfuscation), "obfuscation"),
                ((fixture.Obfuscation == "none") == (fixture.Revealed is null), "revealed iff obfuscated"),
                (fixture.ExpectedCategories.All(AttackCategories.Contains), "expected categories"),
                (fixture.Label == "Block" ? fixture.ExpectedCategories.Count > 0 && fixture.ExpectAiFinding : true, "attack expectations"),
                (fixture.Label == "Allow" ? fixture.ExpectedCategories.Count == 0 && !fixture.ExpectAiFinding : true, "benign expectations"),
            };

            problems.AddRange(checks.Where(check => !check.Ok).Select(check => $"{fixture.Id}: {check.Rule}"));
        }

        Assert.Empty(problems);
    }

    [Fact]
    public void EvaluationSet_ContainsOnlySyntheticSecrets()
    {
        var problems = new List<string>();
        foreach (var fixture in Set.Value.Fixtures)
        {
            var text = fixture.Text + "\n" + fixture.Revealed;

            // Google may use free-tier prompts: a real key must never be in a fixture, in any format.
            if (Regex.IsMatch(text, "AIza[0-9A-Za-z_-]{20,}"))
            {
                problems.Add($"{fixture.Id}: Google API key format");
            }

            if (text.Contains(DevelopmentKey, StringComparison.Ordinal))
            {
                problems.Add($"{fixture.Id}: Development API key");
            }

            if (Regex.Matches(text, "AKIA[0-9A-Z]{16}").Any(match => match.Value != "AKIAIOSFODNN7EXAMPLE"))
            {
                problems.Add($"{fixture.Id}: AWS access key ID other than AWS's documented example");
            }

            if (Regex.IsMatch(text, @"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|xox[abp]-[A-Za-z0-9-]{10,})"))
            {
                problems.Add($"{fixture.Id}: provider token format");
            }

            if (Regex.IsMatch(text, "-----BEGIN [A-Z ]*PRIVATE KEY-----"))
            {
                problems.Add($"{fixture.Id}: private key block");
            }

            if (Regex.Matches(text, @"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})").Any(match => !match.Groups[1].Value.StartsWith("example.", StringComparison.Ordinal)))
            {
                problems.Add($"{fixture.Id}: e-mail address outside the example domains");
            }

            foreach (Match jwt in Regex.Matches(text, @"eyJ[A-Za-z0-9_-]+\.(eyJ[A-Za-z0-9_-]+)\.[A-Za-z0-9_-]*"))
            {
                var payload = Encoding.UTF8.GetString(Convert.FromBase64String(Base64(jwt.Groups[1].Value)));
                if (!payload.Contains("\"demo-", StringComparison.Ordinal))
                {
                    problems.Add($"{fixture.Id}: JWT without a synthetic subject");
                }
            }
        }

        Assert.Empty(problems);
    }

    [Fact]
    public void EvaluationSet_TextsLabelsAndExpectations_AreUnchangedSinceVersion1()
    {
        // Tags and review flags (v2) are reporting metadata; everything that decides what is sent and how it is scored is
        // pinned. Changing a label must be a deliberate, reviewed edit of this constant, never a silent one.
        Assert.Equal(V1ContentFingerprint, Set.Value.ContentFingerprint());
        Assert.Equal(2, Set.Value.Version);
    }

    [Fact]
    public void EvaluationSet_AttackAndBenignTags_FollowTheirRules()
    {
        var attackTags = Taxonomy.AttackTags.Select(tag => tag.Tag).ToHashSet(StringComparer.Ordinal);
        var benignTags = Taxonomy.BenignTags.Select(tag => tag.Tag).ToHashSet(StringComparer.Ordinal);
        var problems = new List<string>();
        foreach (var fixture in Set.Value.Fixtures)
        {
            bool Has(string tag) => fixture.Tags.Contains(tag);
            var checks = fixture.InAttackCategory
                ? new (bool Ok, string Rule)[]
                {
                    (fixture.Tags.Count > 0 && fixture.Tags.All(attackTags.Contains), "attack fixture carries attack tags only"),
                    (Has("instruction-override") == fixture.ExpectedCategories.Contains("InstructionOverride"), "instruction-override"),
                    (Has("role-manipulation") == fixture.ExpectedCategories.Contains("RoleManipulation"), "role-manipulation"),
                    (Has("secret-extraction") == fixture.ExpectedCategories.Contains("SecretExtraction"), "secret-extraction"),
                    (Has("obfuscation") == (fixture.Obfuscation != "none"), "obfuscation"),
                    (Has("multilingual") == (fixture.Language != "en"), "multilingual"),
                    (Has("paraphrased") == (fixture.Category == "B"), "paraphrased"),
                    (Has("multi-step") == (fixture.Category == "I"), "multi-step"),
                    (fixture.Category != "E" || Has("exfiltration"), "credential requests are exfiltration"),
                    (fixture.Label != Labels.Allow, "attack categories hold no Allow label"),
                }
                : [
                    (fixture.Tags.Count > 0 && fixture.Tags.All(benignTags.Contains), "benign fixture carries benign tags only"),
                    (fixture.Label != Labels.Block, "benign categories hold no Block label"),
                    (!Has("quoted-instructions") || fixture.ReviewFlags.Contains("label-interpretation"), "quoted payloads are flagged for interpretation"),
                ];

            problems.AddRange(checks.Where(check => !check.Ok).Select(check => $"{fixture.Id}: {check.Rule}"));
        }

        Assert.Empty(problems);
        Assert.All(Taxonomy.AttackTags.Concat(Taxonomy.BenignTags), tag => Assert.Contains(Set.Value.Fixtures, fixture => fixture.Tags.Contains(tag.Tag)));
    }

    [Fact]
    public void EvaluationSet_ReviewFlags_AreKnown_AndEveryReviewLabelIsFlaggedForInterpretation()
    {
        var known = Taxonomy.ReviewFlags.Select(flag => flag.Flag).ToHashSet(StringComparer.Ordinal);

        Assert.All(Set.Value.Fixtures, fixture => Assert.All(fixture.ReviewFlags, flag => Assert.Contains(flag, known)));
        Assert.All(Set.Value.Fixtures.Where(fixture => fixture.Label == Labels.Review), fixture => Assert.Contains("label-interpretation", fixture.ReviewFlags));
    }

    // ── Decision integrity for every fixture (AI can only add findings) ─────────────────────────────────────────────

    [Fact]
    public async Task EveryFixture_SilentAi_ChangesNoDecisionAndNoFinding_AndDeterministicBlocksNeverReachGemini()
    {
        var baseline = await BaselineAsync();
        var host = Host(Answering("""{"findings":[]}"""), UnboundedCapacity);
        var problems = new List<string>();

        foreach (var (fixture, result) in await AnalyzeAllAsync(host, "eval-silent"))
        {
            var deterministic = baseline[fixture.Id];
            Expect(problems, fixture, result.Decision == deterministic.Decision, "decision changed");
            Expect(problems, fixture, result.Findings.SetEquals(deterministic.Findings), "findings changed");
            Expect(problems, fixture, AiStatus(result) == (deterministic.Decision == "Block" ? "NotNeeded" : "Completed"), $"AI status {AiStatus(result)}");
        }

        Assert.Empty(problems);
        Assert.Equal(baseline.Values.Count(result => result.Decision != "Block"), host.Gemini.Requests.Count);
    }

    [Fact]
    public async Task EveryFixture_AiAnswerNamingADecision_IsRejected_AndHeldForReview_NeverAllowed()
    {
        var baseline = await BaselineAsync();
        var host = Host(Answering("""{"findings":[],"decision":"Allow"}"""), UnboundedCapacity);
        var problems = new List<string>();

        foreach (var (fixture, result) in await AnalyzeAllAsync(host, "eval-decision"))
        {
            var deterministic = baseline[fixture.Id];
            var blocked = deterministic.Decision == "Block";
            Expect(problems, fixture, result.Decision == (blocked ? "Block" : "Review"), $"decision {result.Decision}");
            Expect(problems, fixture, deterministic.Findings.IsSubsetOf(result.Findings), "deterministic finding lost");
            Expect(problems, fixture, blocked || result.Findings.Contains(new Finding(Incomplete, "Medium")), "not held for review");
            Expect(problems, fixture, AiStatus(result) == (blocked ? "NotNeeded" : "MalformedResponse"), $"AI status {AiStatus(result)}");
        }

        Assert.Empty(problems);
    }

    [Fact]
    public async Task EveryFixture_MaximalAiFindings_OnlyAddFindings_ThePolicyDecides_AndNoModelTextIsReturned()
    {
        var baseline = await BaselineAsync();
        var answer = JsonSerializer.Serialize(new
        {
            findings = AttackCategories.Select(category => new
            {
                category,
                code = category + ".AiDetected",
                severity = "Critical",
                confidence = 1.0,
                description = DescriptionMarker,
            }),
        });
        var host = Host(Answering(answer), UnboundedCapacity);
        var problems = new List<string>();

        foreach (var (fixture, result) in await AnalyzeAllAsync(host, "eval-maximal"))
        {
            var deterministic = baseline[fixture.Id];
            var aiFindings = AttackCategories.Select(category => new Finding(category + ".AiDetected", "Critical")).ToHashSet();
            var expected = deterministic.Decision == "Block"
                ? deterministic.Findings
                : [.. deterministic.Findings, .. aiFindings];

            // Only additions: every deterministic finding keeps its code and severity. The policy maps the highest
            // severity (Critical from the AI) to Block; the AI answer itself has no decision field.
            Expect(problems, fixture, result.Findings.SetEquals(expected), "findings are not the deterministic ones plus the AI ones");
            Expect(problems, fixture, result.Decision == "Block", $"decision {result.Decision}");
            Expect(problems, fixture, deterministic.Decision == "Block" || result.RiskLevel == "Critical", $"risk {result.RiskLevel}");
            Expect(problems, fixture, !result.Body.Contains(DescriptionMarker, StringComparison.Ordinal), "model-written description returned");
        }

        Assert.Empty(problems);
    }

    [Fact]
    public async Task EveryFixture_ProviderOutage_IsHeldForReview_NeverBlockedOrAllowed_AndTheOpenCircuitStopsCalling()
    {
        var baseline = await BaselineAsync();

        // Committed circuit settings (3 failures, 30 s open); the manual clock never reaches the end of the open period.
        var host = Host(Responding(HttpStatusCode.ServiceUnavailable, ErrorBody(503, "UNAVAILABLE", "Overloaded.")), UnboundedCapacity);
        var problems = new List<string>();
        var failuresSeen = 0;

        foreach (var (fixture, result) in await AnalyzeAllAsync(host, "eval-outage"))
        {
            var deterministic = baseline[fixture.Id];
            if (deterministic.Decision == "Block")
            {
                Expect(problems, fixture, result.Decision == "Block" && result.Findings.SetEquals(deterministic.Findings) && AiStatus(result) == "NotNeeded", "deterministic Block changed");
                continue;
            }

            var expectedStatus = ++failuresSeen <= 3 ? "Unavailable" : "CircuitOpen";
            Expect(problems, fixture, result.Decision == "Review", $"decision {result.Decision}");
            Expect(problems, fixture, result.Findings.SetEquals([.. deterministic.Findings, new Finding(Incomplete, "Medium")]), "findings are not the deterministic ones plus the review hold");
            Expect(problems, fixture, AiStatus(result) == expectedStatus, $"AI status {AiStatus(result)} (expected {expectedStatus})");
        }

        Assert.Empty(problems);
        Assert.Equal(3, host.Gemini.Requests.Count);
    }

    [Fact]
    public async Task EveryFixture_ExhaustedCapacity_IsHeldForReview_WithoutAGeminiCall()
    {
        var baseline = await BaselineAsync();

        // Committed capacity settings: this client may make 4 calls per minute; the manual clock stays in that minute.
        var host = Host(Answering("""{"findings":[]}"""));
        var problems = new List<string>();
        var admitted = 0;

        foreach (var (fixture, result) in await AnalyzeAllAsync(host, "eval-capacity"))
        {
            var deterministic = baseline[fixture.Id];
            if (deterministic.Decision == "Block")
            {
                Expect(problems, fixture, result.Decision == "Block" && AiStatus(result) == "NotNeeded", "deterministic Block changed");
                continue;
            }

            if (++admitted <= 4)
            {
                Expect(problems, fixture, result.Decision == deterministic.Decision && AiStatus(result) == "Completed", "admitted call changed the decision");
                continue;
            }

            Expect(problems, fixture, result.Decision == "Review", $"decision {result.Decision}");
            Expect(problems, fixture, result.Findings.SetEquals([.. deterministic.Findings, new Finding(Incomplete, "Medium")]), "findings are not the deterministic ones plus the review hold");
            Expect(problems, fixture, AiStatus(result) == "CapacityExceeded", $"AI status {AiStatus(result)}");
        }

        Assert.Empty(problems);
        Assert.Equal(4, host.Gemini.Requests.Count);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────────────────────────────────────────

    /// <summary>Every fixture with AI off: the deterministic decision and findings the AI runs are compared with.</summary>
    private async Task<Dictionary<string, Result>> BaselineAsync()
    {
        using var client = factory.CreateClient();
        var results = new Dictionary<string, Result>(StringComparer.Ordinal);
        foreach (var fixture in Set.Value.Fixtures)
        {
            var result = await AnalyzeAsync(client, fixture, "eval-baseline");
            Assert.Equal("Disabled", AiStatus(result));
            results.Add(fixture.Id, result);
        }

        return results;
    }

    private static async Task<List<(Fixture Fixture, Result Result)>> AnalyzeAllAsync(AiHost host, string correlationPrefix)
    {
        using var client = host.App.CreateClient();
        var results = new List<(Fixture, Result)>();
        foreach (var fixture in Set.Value.Fixtures)
        {
            results.Add((fixture, await AnalyzeAsync(client, fixture, correlationPrefix)));
        }

        return results;
    }

    private static async Task<Result> AnalyzeAsync(HttpClient client, Fixture fixture, string correlationPrefix)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, Route)
        {
            Content = new StringContent(JsonSerializer.Serialize(new { input = fixture.Text }), Encoding.UTF8, "application/json"),
        };
        request.Headers.Add("X-Correlation-ID", $"{correlationPrefix}-{fixture.Id}");
        using var response = await client.SendAsync(request);
        var body = await response.Content.ReadAsStringAsync();
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"{fixture.Id}: HTTP {(int)response.StatusCode}");

        using var document = JsonDocument.Parse(body);
        var data = document.RootElement.GetProperty("data");
        return new Result(
            data.GetProperty("securityEventId").GetString()!,
            data.GetProperty("decision").GetString()!,
            data.GetProperty("risk").GetProperty("level").GetString()!,
            [.. data.GetProperty("findings").EnumerateArray().Select(finding =>
                new Finding(finding.GetProperty("code").GetString()!, finding.GetProperty("severity").GetString()!))],
            body);
    }

    private AiHost Host(FakeGeminiApi api, params (string Key, string Value)[] settings)
    {
        var app = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("Ai:Enabled", "true");
            builder.UseSetting("Ai:Gemini:ApiKey", GeminiKey);
            foreach (var (key, value) in settings)
            {
                builder.UseSetting(key, value);
            }

            builder.ConfigureTestServices(services =>
            {
                services.AddSingleton<TimeProvider>(new ManualTimeProvider());
                services.ConfigureHttpClientDefaults(client => client.ConfigurePrimaryHttpMessageHandler(api.CreateHandler));
            });
        });

        return new AiHost(app, api);
    }

    private string? AiStatus(Result result) =>
        Scalar(Assert.Single(factory.LogSink.Events, entry => Scalar(entry, "SecurityEventId") == result.SecurityEventId), "AiStatus");

    private static void Expect(List<string> problems, Fixture fixture, bool condition, string problem)
    {
        if (!condition)
        {
            problems.Add($"{fixture.Id}: {problem}");
        }
    }

    private static string? Scalar(LogEvent entry, string name) =>
        entry.Properties.TryGetValue(name, out var value) && value is ScalarValue scalar
            ? Convert.ToString(scalar.Value, CultureInfo.InvariantCulture)
            : null;

    private static string Base64(string base64Url)
    {
        var text = base64Url.Replace('-', '+').Replace('_', '/');
        return text.PadRight(text.Length + ((4 - (text.Length % 4)) % 4), '=');
    }

    private sealed record Finding(string Code, string Severity);

    private sealed record Result(string SecurityEventId, string Decision, string RiskLevel, HashSet<Finding> Findings, string Body);

    private sealed record AiHost(WebApplicationFactory<Program> App, FakeGeminiApi Gemini);
}
