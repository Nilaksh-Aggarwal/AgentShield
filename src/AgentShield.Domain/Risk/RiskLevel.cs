namespace AgentShield.Domain.Risk;

/// <summary>
/// Overall risk of an analysed input, derived from its <see cref="RiskAssessment.Score"/> (see the bands there), or of an
/// agent action, classified from its declared effects (<see cref="Agents.ActionEffects"/>; no score).
/// Values are ordered so levels can be compared; the API writes the names.
/// </summary>
public enum RiskLevel
{
    /// <summary>Score 0–29.</summary>
    Low = 1,

    /// <summary>Score 30–69.</summary>
    Medium = 2,

    /// <summary>Score 70–89.</summary>
    High = 3,

    /// <summary>Score 90–100.</summary>
    Critical = 4,
}
