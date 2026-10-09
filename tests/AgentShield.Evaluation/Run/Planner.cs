using System.Security.Cryptography;
using System.Text;
using AgentShield.Evaluation.Dataset;
using AgentShield.Evaluation.Results;

namespace AgentShield.Evaluation.Run;

internal enum Subset
{
    All,

    /// <summary>Categories A–I (attacks and the ambiguous request E07).</summary>
    Attacks,

    /// <summary>Categories J–P (benign content, including the two quoted-payload documents labelled Review).</summary>
    Benign,
}

internal sealed record PlannedFixture(Fixture Fixture, bool NeedsAi, int PreviousAttempts);

/// <summary>What a session will send, in order. Nothing that already has a valid result is in it.</summary>
internal sealed record EvaluationPlan(
    Subset Subset,
    IReadOnlyList<PlannedFixture> Order,
    int InSubset,
    int AlreadyValid,
    int ZeroCall,
    int NeverAttempted,
    int PreviouslyFailed,
    int ExcludedFailed)
{
    public int AiCallsNeeded => Order.Count(item => item.NeedsAi);
}

internal static class Planner
{
    /// <summary>
    /// Fixtures in <paramref name="subset"/> without a valid attempt (AI completed, or not needed for a deterministic
    /// Block), in this order: deterministic Blocks (zero provider calls), fixtures never attempted, then fixtures whose
    /// earlier attempts failed (last, so one input that keeps failing cannot hold up the rest; left out entirely with
    /// <paramref name="excludeFailed"/>). Each group keeps a fixed, interleaved order.
    /// </summary>
    public static EvaluationPlan Create(
        EvaluationDataset dataset,
        IReadOnlyDictionary<string, BaselineRecord> baseline,
        IReadOnlyList<AttemptRecord> attempts,
        Subset subset,
        bool excludeFailed)
    {
        var inSubset = dataset.Fixtures.Where(fixture => subset switch
        {
            Subset.Attacks => fixture.InAttackCategory,
            Subset.Benign => !fixture.InAttackCategory,
            _ => true,
        }).ToList();

        var byFixture = attempts.GroupBy(attempt => attempt.FixtureId, StringComparer.Ordinal)
            .ToDictionary(group => group.Key, group => group.ToList(), StringComparer.Ordinal);
        List<PlannedFixture> zeroCall = [], neverAttempted = [], previouslyFailed = [];
        var alreadyValid = 0;
        var excluded = 0;
        foreach (var fixture in inSubset.OrderBy(fixture => OrderKey(fixture.Id), StringComparer.Ordinal))
        {
            var earlier = byFixture.GetValueOrDefault(fixture.Id) ?? [];
            if (earlier.Exists(attempt => attempt.Valid))
            {
                alreadyValid++;
                continue;
            }

            var needsAi = baseline[fixture.Id].Decision != Labels.Block;
            var planned = new PlannedFixture(fixture, needsAi, earlier.Count);
            if (!needsAi)
            {
                zeroCall.Add(planned);
            }
            else if (earlier.Count == 0)
            {
                neverAttempted.Add(planned);
            }
            else if (excludeFailed)
            {
                excluded++;
            }
            else
            {
                previouslyFailed.Add(planned);
            }
        }

        return new EvaluationPlan(
            subset, [.. zeroCall, .. neverAttempted, .. previouslyFailed], inSubset.Count, alreadyValid, zeroCall.Count,
            neverAttempted.Count, previouslyFailed.Count, excluded);
    }

    /// <summary>Fixed across dataset versions (the salt names v1), so a resumed run keeps the Milestone 7 order.</summary>
    public static string OrderKey(string fixtureId) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("agentshield-ai-evaluation/v1/" + fixtureId)));
}
