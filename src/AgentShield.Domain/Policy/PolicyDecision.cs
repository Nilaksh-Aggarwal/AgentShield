namespace AgentShield.Domain.Policy;

/// <summary>The outcome of the deterministic policy: a decision and the rule that produced it.</summary>
/// <param name="Decision">What the caller should do with the input.</param>
/// <param name="RuleCode">Stable identifier of the policy rule that decided (e.g. <c>Policy.BlockHighRisk</c>).</param>
/// <param name="Reason">Client-safe explanation of the decision. Never contains analysed content.</param>
public sealed record PolicyDecision(SecurityDecision Decision, string RuleCode, string Reason)
{
    public SecurityDecision Decision { get; } = Enum.IsDefined(Decision)
        ? Decision
        : throw new ArgumentOutOfRangeException(nameof(Decision), Decision, "Unknown security decision.");

    public string RuleCode { get; } = string.IsNullOrWhiteSpace(RuleCode)
        ? throw new ArgumentException("A policy rule code is required.", nameof(RuleCode))
        : RuleCode;

    public string Reason { get; } = string.IsNullOrWhiteSpace(Reason)
        ? throw new ArgumentException("A reason is required.", nameof(Reason))
        : Reason;
}
