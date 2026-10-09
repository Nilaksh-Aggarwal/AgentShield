namespace AgentShield.Domain.Policy;

/// <summary>
/// What the caller should do with the analysed input. A domain result, not an HTTP status: a successful analysis that
/// decides <see cref="Block"/> is still a successful operation.
/// </summary>
public enum SecurityDecision
{
    /// <summary>No threat that the policy acts on; the input may proceed.</summary>
    Allow = 1,

    /// <summary>Suspicious; hold the input for human review before it proceeds.</summary>
    Review = 2,

    /// <summary>The input must not reach the model or agent.</summary>
    Block = 3,
}
