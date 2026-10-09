using System.Text.RegularExpressions;
using AgentShield.Evaluation.Reliability;

namespace AgentShield.IntegrationTests.Evaluation;

/// <summary>
/// The reliability sets (tests/Evaluation/reliability): the held-out split is pinned, the splits stay apart, and the
/// stored results are what the code decides today, so a rule change cannot leave stale evidence behind. No provider is
/// ever called.
/// </summary>
public sealed partial class ReliabilitySetTests
{
    /// <summary>Content fingerprint of held-out v1, written 2026-10-09 before any rule change. It never changes.</summary>
    private const string HeldOutV1Fingerprint = "bb758c1ab300558a33a49b5fe4ab6211e77fa1ac9fc5fbe6a2a10f0ce0515d11";

    private static readonly string[] Splits = [ReliabilityDataset.HeldOut, ReliabilityDataset.Tuning, ReliabilityDataset.Legacy];

    private static readonly string[] Sources = ["user", "web", "email", "markdown", "api", "code", "ocr", "document"];

    [Fact]
    public void HeldOut_IsUnchangedSinceItWasWritten()
    {
        Assert.Equal(HeldOutV1Fingerprint, ReliabilityDataset.Load(ReliabilityDataset.HeldOut).ContentFingerprint());
    }

    [Theory]
    [InlineData(ReliabilityDataset.HeldOut, "HO-", "HB-")]
    [InlineData(ReliabilityDataset.Tuning, "TU-", "TB-")]
    public void Split_IsWellFormed(string split, string attackPrefix, string benignPrefix)
    {
        var dataset = ReliabilityDataset.Load(split);

        Assert.Equal(split, dataset.Split);
        Assert.Equal(dataset.Fixtures.Count, dataset.Fixtures.Select(fixture => fixture.Id).Distinct(StringComparer.Ordinal).Count());
        Assert.All(dataset.Fixtures, fixture =>
        {
            Assert.Contains(fixture.Source, Sources);
            Assert.InRange(fixture.Text.Length, 1, 32_000);
            if (fixture.Positive)
            {
                Assert.Equal(("Block", true), (fixture.Label, fixture.Id.StartsWith(attackPrefix, StringComparison.Ordinal)));
                Assert.Contains(fixture.Category, ReliabilityDataset.AttackCategories);
            }
            else
            {
                Assert.Equal(("Allow", true), (fixture.Label, fixture.Id.StartsWith(benignPrefix, StringComparison.Ordinal)));
                Assert.Contains(fixture.Category, ReliabilityDataset.BenignCategories);
            }
        });
    }

    [Fact]
    public void Splits_ShareNoInputAndNoNearDuplicate()
    {
        var heldOut = ReliabilityDataset.Load(ReliabilityDataset.HeldOut).Fixtures;
        var tuning = ReliabilityDataset.Load(ReliabilityDataset.Tuning).Fixtures;

        Assert.Empty(heldOut.Select(fixture => fixture.Id).Intersect(tuning.Select(fixture => fixture.Id), StringComparer.Ordinal));
        var closest = heldOut
            .SelectMany(held => tuning.Select(tuned => (held.Id, tuned.Id, Similarity: Jaccard(Words(held.Text), Words(tuned.Text)))))
            .MaxBy(pair => pair.Similarity);
        Assert.True(closest.Similarity <= 0.5, $"{closest.Item1} and {closest.Item2} are near duplicates ({closest.Similarity:0.00}).");
    }

    [Theory]
    [InlineData(ReliabilityDataset.HeldOut)]
    [InlineData(ReliabilityDataset.Tuning)]
    public void Split_ContainsNoRealLookingSecret(string split)
    {
        Assert.All(ReliabilityDataset.Load(split).Fixtures, fixture => Assert.False(SecretLike().IsMatch(fixture.Text), fixture.Id));
    }

    [Fact]
    public async Task StoredDeterministicResults_AreWhatTheRulesDecideToday()
    {
        foreach (var split in Splits)
        {
            var stored = ReliabilityRunner.LoadRun(ReliabilityRunner.RunFile("final", split, ReliabilityMode.Deterministic));
            Assert.NotNull(stored);
            var dataset = ReliabilityDataset.Load(split);
            Assert.Equal(dataset.ContentFingerprint(), stored.DatasetFingerprint);

            var live = await ReliabilityRunner.RunAsync(dataset, ReliabilityMode.Deterministic, "test");

            Assert.Equal(0, live.SimulatedProviderResponses);
            Assert.Equal(Decisions(stored), Decisions(live));
        }
    }

    [Fact]
    public async Task DeterministicRun_IsRepeatable()
    {
        var dataset = ReliabilityDataset.Load(ReliabilityDataset.HeldOut);

        var first = await ReliabilityRunner.RunAsync(dataset, ReliabilityMode.Deterministic, "test");
        var second = await ReliabilityRunner.RunAsync(dataset, ReliabilityMode.Deterministic, "test");

        Assert.Equal(Decisions(first), Decisions(second));
    }

    [Fact]
    public async Task UnavailableProvider_NeverAllows_AndKeepsEveryDeterministicBlock()
    {
        var dataset = ReliabilityDataset.Load(ReliabilityDataset.HeldOut);

        var deterministic = await ReliabilityRunner.RunAsync(dataset, ReliabilityMode.Deterministic, "test");
        var unavailable = await ReliabilityRunner.RunAsync(dataset, ReliabilityMode.AiUnavailable, "test");

        Assert.All(unavailable.Outcomes, outcome => Assert.Equal(200, outcome.Status));
        Assert.DoesNotContain(unavailable.Outcomes, outcome => outcome.Decision == "Allow");
        var blocked = deterministic.Outcomes.Where(outcome => outcome.Decision == "Block").Select(outcome => outcome.Id).ToHashSet(StringComparer.Ordinal);
        Assert.All(unavailable.Outcomes, outcome => Assert.Equal(blocked.Contains(outcome.Id) ? "Block" : "Review", outcome.Decision));
    }

    private static string[] Decisions(ReliabilityRun run) =>
        [.. run.Outcomes.Select(outcome => $"{outcome.Id}|{outcome.Status}|{outcome.Decision}|{string.Join(',', outcome.Codes)}")];

    private static HashSet<string> Words(string text) =>
        [.. WordPattern().Matches(text.ToLowerInvariant()).Select(match => match.Value).Where(word => word.Length > 2)];

    private static double Jaccard(HashSet<string> a, HashSet<string> b)
    {
        var shared = a.Count(b.Contains);
        var union = a.Count + b.Count - shared;
        return union == 0 ? 0 : (double)shared / union;
    }

    [GeneratedRegex("[a-z0-9]+")]
    private static partial Regex WordPattern();

    [GeneratedRegex(@"AIza[0-9A-Za-z_-]{35}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36}|-----BEGIN [A-Z ]*PRIVATE KEY|sk-[A-Za-z0-9]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")]
    private static partial Regex SecretLike();
}
