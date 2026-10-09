namespace AgentShield.Domain.Threats;

/// <summary>
/// How much harm a single finding indicates if the input reached a model or agent unchanged.
/// </summary>
/// <remarks>
/// Values are ordered (a larger value is more severe) so severities can be compared; the numbers carry no other
/// meaning and are never exposed (the API writes the names). Severity describes one finding; the overall risk of an
/// input is a <see cref="Risk.RiskAssessment"/>, and neither is an HTTP concept.
/// </remarks>
public enum ThreatSeverity
{
    /// <summary>Suspicious wording with a plausible benign reading. Worth recording, not worth stopping.</summary>
    Low = 1,

    /// <summary>A likely manipulation attempt whose impact is limited or uncertain. A human should look.</summary>
    Medium = 2,

    /// <summary>A clear attempt to subvert the model's instructions or extract protected data.</summary>
    High = 3,

    /// <summary>An unambiguous attack on the trust boundary (e.g. forged system/role delimiters).</summary>
    Critical = 4,
}
