using AgentShield.Domain.Agents;
using AgentShield.Domain.Risk;
using AgentShield.Security.Agents;

namespace AgentShield.SecurityTests.Agents;

/// <summary>
/// The action risk classifier against its specification, over every possible combination of declared effects: the level of
/// the most dangerous effect, never lower when effects are added, never Low for anything it cannot classify.
/// </summary>
public sealed class ActionRiskClassifierTests
{
    // The specification (docs/security/agent-action-authorization.md), written out independently of the implementation.
    private static readonly Dictionary<ActionEffects, RiskLevel> Specified = new()
    {
        [ActionEffects.ReadOnly] = RiskLevel.Low,
        [ActionEffects.MetadataLookup] = RiskLevel.Low,
        [ActionEffects.ModifiesData] = RiskLevel.Medium,
        [ActionEffects.DraftForApproval] = RiskLevel.Medium,
        [ActionEffects.ExternalCommunication] = RiskLevel.High,
        [ActionEffects.ModifiesSensitiveData] = RiskLevel.High,
        [ActionEffects.PrivilegedOperation] = RiskLevel.High,
        [ActionEffects.Financial] = RiskLevel.Critical,
        [ActionEffects.CredentialAccess] = RiskLevel.Critical,
        [ActionEffects.Destructive] = RiskLevel.Critical,
        [ActionEffects.PrivilegeChange] = RiskLevel.Critical,
    };

    private static readonly ActionEffects[] Effects = [.. Specified.Keys];

    [Theory]
    [InlineData(ActionEffects.ReadOnly, RiskLevel.Low)]
    [InlineData(ActionEffects.MetadataLookup, RiskLevel.Low)]
    [InlineData(ActionEffects.ModifiesData, RiskLevel.Medium)]
    [InlineData(ActionEffects.DraftForApproval, RiskLevel.Medium)]
    [InlineData(ActionEffects.ExternalCommunication, RiskLevel.High)]
    [InlineData(ActionEffects.ModifiesSensitiveData, RiskLevel.High)]
    [InlineData(ActionEffects.PrivilegedOperation, RiskLevel.High)]
    [InlineData(ActionEffects.Financial, RiskLevel.Critical)]
    [InlineData(ActionEffects.CredentialAccess, RiskLevel.Critical)]
    [InlineData(ActionEffects.Destructive, RiskLevel.Critical)]
    [InlineData(ActionEffects.PrivilegeChange, RiskLevel.Critical)]
    public void Classify_EachEffectAlone_HasItsSpecifiedLevel(ActionEffects effect, RiskLevel expected)
    {
        Assert.Equal(expected, ActionRiskClassifier.Classify(effect));
    }

    [Fact]
    public void Classify_EveryCombinationOfEffects_IsTheHighestLevelAmongThem()
    {
        var checkedCombinations = 0;
        for (var mask = 1; mask < 1 << Effects.Length; mask++)
        {
            var effects = Combination(mask);
            var expected = Effects.Where(effect => (effects & effect) != 0).Max(effect => Specified[effect]);

            Assert.Equal(expected, ActionRiskClassifier.Classify(effects));
            checkedCombinations++;
        }

        Assert.Equal(2047, checkedCombinations);
    }

    [Fact]
    public void Classify_AddingAnyEffect_NeverLowersTheLevel()
    {
        for (var mask = 1; mask < 1 << Effects.Length; mask++)
        {
            var effects = Combination(mask);
            var level = ActionRiskClassifier.Classify(effects);

            Assert.All(Effects, effect => Assert.True(ActionRiskClassifier.Classify(effects | effect) >= level));
        }
    }

    [Fact]
    public void Classify_AReadEffectBesideADangerousOne_DoesNotDiluteIt()
    {
        Assert.Equal(RiskLevel.Critical, ActionRiskClassifier.Classify(ActionEffects.ReadOnly | ActionEffects.CredentialAccess));
        Assert.Equal(RiskLevel.High, ActionRiskClassifier.Classify(ActionEffects.MetadataLookup | ActionEffects.DraftForApproval | ActionEffects.ExternalCommunication));
    }

    [Fact]
    public void Classify_NoEffect_Throws_BecauseUnclassifiedIsNeverLow()
    {
        Assert.Throws<ArgumentException>(() => ActionRiskClassifier.Classify(ActionEffects.None));
    }

    [Theory]
    [InlineData(1 << 11)]
    [InlineData((1 << 11) | 1)]
    [InlineData(1 << 30)]
    [InlineData(-1)]
    public void Classify_UnknownEffectBits_Throw_EvenBesideKnownOnes(int effects)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => ActionRiskClassifier.Classify((ActionEffects)effects));
    }

    [Fact]
    public void Unclassified_IsTheHighestLevel()
    {
        Assert.Equal(RiskLevel.Critical, ActionRiskClassifier.Unclassified);
        Assert.Equal(ActionRiskClassifier.Unclassified, Enum.GetValues<RiskLevel>().Max());
    }

    private static ActionEffects Combination(int mask)
    {
        var effects = ActionEffects.None;
        for (var bit = 0; bit < Effects.Length; bit++)
        {
            if ((mask & (1 << bit)) != 0)
            {
                effects |= Effects[bit];
            }
        }

        return effects;
    }
}
