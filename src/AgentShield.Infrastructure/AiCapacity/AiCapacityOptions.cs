namespace AgentShield.Infrastructure.AiCapacity;

/// <summary>
/// AgentShield's own budget for AI-assisted analysis (section <c>Ai:Capacity</c>). Validated at startup when
/// <c>Ai:Enabled</c> is true; see docs/security/ai-analysis.md, section 16.
/// </summary>
/// <remarks>
/// <para>These are AgentShield safety budgets, deliberately set below the provider's quota, which is shared by everything
/// using the same provider project. They are not the provider's limits, and no provider limit is hard-coded anywhere.</para>
/// <para>No value has a default: with AI enabled, a missing value fails startup instead of being invented.</para>
/// </remarks>
public sealed class AiCapacityOptions
{
    public const string SectionName = "Ai:Capacity";

    /// <summary>AI calls admitted in any rolling 60-second period, all clients together.</summary>
    public int GlobalRequestsPerMinute { get; set; }

    /// <summary>AI calls admitted in any rolling 24-hour period, all clients together.</summary>
    public int GlobalRequestsPerDay { get; set; }

    /// <summary>AI calls in flight at the same time, all clients together. There is no queue.</summary>
    public int MaxConcurrentCalls { get; set; }

    /// <summary>
    /// Estimated input tokens admitted in any rolling 60-second period, all clients together. Each admitted call
    /// reserves the provider adapter's conservative upper-bound estimate (never a provider count).
    /// </summary>
    public int GlobalInputTokensPerMinute { get; set; }

    /// <summary>
    /// Whether an input the deterministic policy already blocks skips the AI call (AI findings cannot change a Block).
    /// </summary>
    public bool? SkipWhenDeterministicBlock { get; set; }

    /// <summary>The budget every analysis client gets (per-client configuration does not exist yet).</summary>
    public AiClientCapacityOptions? DefaultClient { get; set; }
}

/// <summary>One client's share of the AI budget (section <c>Ai:Capacity:DefaultClient</c>).</summary>
public sealed class AiClientCapacityOptions
{
    /// <summary>
    /// Calls per rolling minute reserved for the client: other clients can never use them, whether or not this client
    /// has called yet.
    /// </summary>
    public int GuaranteedPerMinute { get; set; }

    /// <summary>Most calls per rolling minute: the guarantee plus whatever it may take from the shared remainder.</summary>
    public int MaxPerMinute { get; set; }

    /// <summary>Calls per rolling 24 hours reserved for the client (the daily counterpart of the minute guarantee).</summary>
    public int GuaranteedPerDay { get; set; }

    /// <summary>Most calls per rolling 24 hours, so that one client cannot spend the whole daily budget.</summary>
    public int MaxPerDay { get; set; }

    /// <summary>The client's calls in flight at the same time.</summary>
    public int MaxConcurrentCalls { get; set; }

    /// <summary>Estimated input tokens per rolling minute reserved for the client; no other client can use them.</summary>
    public int GuaranteedInputTokensPerMinute { get; set; }

    /// <summary>
    /// Most estimated input tokens per rolling minute for the client. A single request estimated above this can never be
    /// admitted and is always held for review.
    /// </summary>
    public int MaxInputTokensPerMinute { get; set; }

    /// <summary>What an analysis becomes when the budget refuses its AI call. Only <see cref="AiCapacityExceededAction.Review"/> exists.</summary>
    public AiCapacityExceededAction WhenExceeded { get; set; }
}

/// <summary>What an analysis becomes when AI capacity is exhausted.</summary>
public enum AiCapacityExceededAction
{
    /// <summary>
    /// Hold the input for review (<c>InconclusiveAnalysis.AiAnalysisIncomplete</c>). The only option on purpose: falling
    /// back to the deterministic decision would let a caller exhaust the budget and then send attacks only AI detects.
    /// </summary>
    Review = 1,
}
