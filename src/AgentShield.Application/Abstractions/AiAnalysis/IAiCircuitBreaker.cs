using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Application.Abstractions.AiAnalysis;

/// <summary>
/// Circuit breaker in front of the AI provider: stops calling a provider that keeps failing for availability reasons
/// (rate limit, outage, network, timeout) and lets exactly one probe call test it again after a pause. Provider-agnostic:
/// it sees only the stage's normalised <see cref="AiAnalysisStatus"/>, never provider status codes, content or callers.
/// </summary>
/// <remarks>
/// <para>Contract for implementations:</para>
/// <list type="bullet">
/// <item>One circuit for the configured provider and model in the process (the only provider <c>AddAI</c> registers).
/// Its state is never created per request and never keyed by anything a client controls.</item>
/// <item>Closed: every call is allowed. Open: no call is allowed. HalfOpen: exactly one probe call at a time; everybody
/// else is refused until the probe's outcome is reported.</item>
/// <item>Only <see cref="AiProviderAvailability.IsAvailabilityFailure"/> outcomes count as failures. Any outcome in which
/// the provider answered (<see cref="AiProviderAvailability.ProviderResponded"/>) counts as proof it is reachable.</item>
/// <item>Never waits, never retries.</item>
/// </list>
/// A refusal decides nothing: the AI stage turns it into the finding that holds the input for review.
/// </remarks>
public interface IAiCircuitBreaker
{
    /// <summary>Whether a provider call may start now. Dispose the permit when the call has ended.</summary>
    AiCircuitPermit TryAcquire();
}

/// <summary>
/// Permission for one provider call. Call <see cref="Report"/> once with the call's normalised outcome; disposing the
/// permit without a report (no call was made, the caller cancelled, the adapter threw) records nothing and frees a
/// probe slot for the next caller.
/// </summary>
public sealed class AiCircuitPermit : IDisposable
{
    private readonly Action<AiAnalysisStatus>? _report;
    private readonly Action? _abandon;
    private int _settled;

    private AiCircuitPermit(bool isAllowed, bool isProbe, TimeSpan? callTimeout, Action<AiAnalysisStatus>? report, Action? abandon)
    {
        IsAllowed = isAllowed;
        IsProbe = isProbe;
        CallTimeout = callTimeout;
        _report = report;
        _abandon = abandon;
    }

    /// <summary>The circuit is open, or a half-open probe is already in flight: do not call the provider.</summary>
    public static AiCircuitPermit Rejected { get; } = new(false, false, null, null, null);

    public bool IsAllowed { get; }

    /// <summary>This call is the half-open probe that decides whether the circuit closes again.</summary>
    public bool IsProbe { get; }

    /// <summary>A tighter bound for this call than the stage's own timeout (the probe timeout), if any.</summary>
    public TimeSpan? CallTimeout { get; }

    /// <summary>A normal call while the circuit is closed.</summary>
    public static AiCircuitPermit Allowed(Action<AiAnalysisStatus> report, Action abandon)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(abandon);
        return new AiCircuitPermit(true, false, null, report, abandon);
    }

    /// <summary>The single half-open probe call, bounded by <paramref name="callTimeout"/>.</summary>
    public static AiCircuitPermit Probe(TimeSpan callTimeout, Action<AiAnalysisStatus> report, Action abandon)
    {
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(callTimeout, TimeSpan.Zero);
        ArgumentNullException.ThrowIfNull(report);
        ArgumentNullException.ThrowIfNull(abandon);
        return new AiCircuitPermit(true, true, callTimeout, report, abandon);
    }

    /// <summary>Reports how the provider call ended. Only the first report or dispose counts.</summary>
    public void Report(AiAnalysisStatus status)
    {
        if (Interlocked.Exchange(ref _settled, 1) == 0)
        {
            _report?.Invoke(status);
        }
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _settled, 1) == 0)
        {
            _abandon?.Invoke();
        }
    }
}

/// <summary>
/// The one classification of provider availability, shared by the failure policy (Security) and the circuit breaker
/// (Infrastructure) so the two cannot drift. Built on the stage's normalised statuses: provider adapters map their own
/// status codes to <see cref="AiAnalysisErrors"/>, and nothing downstream sees a provider-specific code.
/// </summary>
public static class AiProviderAvailability
{
    /// <summary>
    /// The provider could not serve the call: rate or quota limit (e.g. HTTP 429), outage (e.g. 5xx, 503), network
    /// failure, or no answer in time. These open the circuit.
    /// </summary>
    public static bool IsAvailabilityFailure(AiAnalysisStatus status) => status is
        AiAnalysisStatus.RateLimited or AiAnalysisStatus.Unavailable or AiAnalysisStatus.NetworkFailure or AiAnalysisStatus.TimedOut;

    /// <summary>
    /// The provider answered, whatever the answer was: a valid result, a malformed or invalid answer, a refusal, or a
    /// rejected request (e.g. HTTP 400, or a key, permission or model fault such as 401/403/404). These show the provider
    /// is reachable; they never open the circuit.
    /// </summary>
    public static bool ProviderResponded(AiAnalysisStatus status) => status is
        AiAnalysisStatus.Completed or AiAnalysisStatus.MalformedResponse or AiAnalysisStatus.InvalidResponse
        or AiAnalysisStatus.Refused or AiAnalysisStatus.UnclassifiedFailure;
}
