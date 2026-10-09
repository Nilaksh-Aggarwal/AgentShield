using AgentShield.Domain.Policy;

namespace AgentShield.Application.Abstractions.AiAnalysis;

/// <summary>
/// Admission control in front of every AI provider call: AgentShield's own budget for AI-assisted analysis (requests per
/// minute and per day, per-client shares, concurrent calls). The budget is configured below the provider's quota, so
/// AgentShield's traffic never consumes all of a quota that is shared at the provider's project level. Provider-agnostic:
/// it counts calls and knows nothing about any provider.
/// </summary>
/// <remarks>
/// <para>Contract for implementations:</para>
/// <list type="bullet">
/// <item>Never wait. A call that cannot start now is refused; there is no queue.</item>
/// <item>Consume nothing unless the result is <see cref="AiAdmissionStatus.Admitted"/>.</item>
/// <item>Hold an admitted call's concurrency slot until the returned <see cref="AiAdmission"/> is disposed. The caller
/// disposes it when the call has ended, however it ended (answer, failure, timeout, cancellation, exception).</item>
/// <item>Key state by client ID only, never by a credential or by content.</item>
/// </list>
/// <para>A refusal decides nothing. The AI analysis stage turns it into the finding that holds the input for review, so
/// running out of AI capacity can never turn into a silent deterministic-only Allow (docs/security/ai-analysis.md,
/// section 16).</para>
/// </remarks>
public interface IAiCapacityGate
{
    /// <summary>
    /// Whether an AI call is worth making at all for this deterministic decision: <see langword="false"/> for a
    /// deterministic Block when the configuration skips those (AI findings only add, so they cannot change a Block).
    /// Consumes nothing. Asked before anything else (disclosure, circuit breaker, admission).
    /// </summary>
    bool IsCallNeeded(SecurityDecision deterministicDecision);

    /// <summary>Decides, without waiting, whether one AI provider call may start now.</summary>
    AiAdmission TryAdmit(AiAdmissionRequest request);
}

/// <summary>What the gate needs to know about one prospective AI call.</summary>
/// <param name="ClientId">The authenticated client (<see cref="Context.ICallerContext"/>). Never a credential.</param>
/// <param name="DeterministicDecision">The policy decision on the deterministic findings alone. AI findings can only be
/// added to those findings, so when this is already <see cref="SecurityDecision.Block"/> no AI answer can change the
/// decision and the call may not be needed.</param>
/// <param name="EstimatedInputTokens">A conservative upper bound on the input tokens the provider will count for the call
/// (<see cref="IAiSecurityAnalyzer.EstimateInputTokens"/>, never below the stage's provider-agnostic floor). Reserved
/// against the input-token budget on admission. Never a network count.</param>
public sealed record AiAdmissionRequest(string ClientId, SecurityDecision DeterministicDecision, long EstimatedInputTokens);

/// <summary>The gate's answer. Refusal reasons beyond these two kinds are internal (logs and metrics only).</summary>
public enum AiAdmissionStatus
{
    /// <summary>The call may start. It holds a concurrency slot until the admission is disposed.</summary>
    Admitted = 1,

    /// <summary>The call is not needed: the deterministic decision is already Block. No capacity was used.</summary>
    NotNeeded = 2,

    /// <summary>
    /// A request budget (global or per client, per minute or per day) or the input-token budget is spent. Nothing was
    /// consumed.
    /// </summary>
    CapacityExceeded = 3,

    /// <summary>The global or per-client limit of concurrent calls is reached. Nothing was consumed.</summary>
    ConcurrencyExceeded = 4,
}

/// <summary>
/// The result of one admission. Dispose it when the admitted call has ended: that releases its concurrency slot.
/// Disposing twice, or disposing a refusal, does nothing.
/// </summary>
public sealed class AiAdmission : IDisposable
{
    private Action? _release;

    private AiAdmission(AiAdmissionStatus status, Action? release)
    {
        Status = status;
        _release = release;
    }

    public static AiAdmission NotNeeded { get; } = new(AiAdmissionStatus.NotNeeded, null);

    public static AiAdmission CapacityExceeded { get; } = new(AiAdmissionStatus.CapacityExceeded, null);

    public static AiAdmission ConcurrencyExceeded { get; } = new(AiAdmissionStatus.ConcurrencyExceeded, null);

    public AiAdmissionStatus Status { get; }

    /// <summary>An admitted call; <paramref name="release"/> runs once, on the first <see cref="Dispose"/>.</summary>
    public static AiAdmission Admitted(Action release)
    {
        ArgumentNullException.ThrowIfNull(release);
        return new AiAdmission(AiAdmissionStatus.Admitted, release);
    }

    public void Dispose() => Interlocked.Exchange(ref _release, null)?.Invoke();
}
