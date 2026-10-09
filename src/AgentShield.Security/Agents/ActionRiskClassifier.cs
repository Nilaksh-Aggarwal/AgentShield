using AgentShield.Domain.Agents;
using AgentShield.Domain.Risk;

namespace AgentShield.Security.Agents;

/// <summary>
/// Deterministic risk classification of an agent action from its declared effects: the action is as risky as its most
/// dangerous effect. No AI, no score, no name matching.
/// </summary>
/// <remarks>
/// <list type="table">
/// <item><term>Low</term><description>read-only, metadata lookup</description></item>
/// <item><term>Medium</term><description>modifies non-sensitive data, drafts for approval</description></item>
/// <item><term>High</term><description>external communication, modifies sensitive data, privileged operation</description></item>
/// <item><term>Critical</term><description>financial, credential access, destructive, privilege change</description></item>
/// </list>
/// Adding effects never lowers the level. An action that cannot be classified (unknown tool or action) is
/// <see cref="Unclassified"/>, the highest level, never Low.
/// </remarks>
internal static class ActionRiskClassifier
{
    /// <summary>The level of an action AgentShield cannot classify: the highest, so "unknown" is never "safe".</summary>
    public const RiskLevel Unclassified = RiskLevel.Critical;

    private static readonly (ActionEffects Effect, RiskLevel Level)[] Levels =
    [
        (ActionEffects.ReadOnly, RiskLevel.Low),
        (ActionEffects.MetadataLookup, RiskLevel.Low),
        (ActionEffects.ModifiesData, RiskLevel.Medium),
        (ActionEffects.DraftForApproval, RiskLevel.Medium),
        (ActionEffects.ExternalCommunication, RiskLevel.High),
        (ActionEffects.ModifiesSensitiveData, RiskLevel.High),
        (ActionEffects.PrivilegedOperation, RiskLevel.High),
        (ActionEffects.Financial, RiskLevel.Critical),
        (ActionEffects.CredentialAccess, RiskLevel.Critical),
        (ActionEffects.Destructive, RiskLevel.Critical),
        (ActionEffects.PrivilegeChange, RiskLevel.Critical),
    ];

    /// <summary>The risk of an action with <paramref name="effects"/>: the highest level among them.</summary>
    /// <exception cref="ArgumentException">No effect, or an effect this classifier does not know: a definition error,
    /// which fails the request closed rather than classifying it low.</exception>
    public static RiskLevel Classify(ActionEffects effects)
    {
        if (effects == ActionEffects.None)
        {
            throw new ArgumentException("An action without effects cannot be classified.", nameof(effects));
        }

        if ((effects & ~ToolActionDefinition.AllEffects) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(effects), effects, "Unknown action effect.");
        }

        var level = RiskLevel.Low;
        foreach (var (effect, effectLevel) in Levels)
        {
            if ((effects & effect) != 0 && effectLevel > level)
            {
                level = effectLevel;
            }
        }

        return level;
    }
}
