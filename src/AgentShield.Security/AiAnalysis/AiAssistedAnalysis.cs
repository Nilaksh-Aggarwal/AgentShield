using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Abstractions.Context;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Application.Common.Results;
using AgentShield.Domain.Policy;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Domain.Threats;

namespace AgentShield.Security.AiAnalysis;

/// <summary>
/// The guarded AI-assisted analysis stage: Block skip → disclosure policy → input-token estimate → circuit breaker →
/// capacity admission → one provider call under a hard timeout → validation → findings, with every failure mapped by
/// <see cref="AiFailurePolicy"/>. Every provider goes through this class, so no adapter can skip the capacity gate, the
/// circuit breaker, the timeout, the validation or the failure handling.
/// </summary>
/// <remarks>
/// <para>AI analysis is enabled by registering an <see cref="IAiSecurityAnalyzer"/>. The parameter is optional on
/// purpose: with no provider registered, the container passes <see langword="null"/> and the stage reports
/// <see cref="AiAnalysisStatus.Disabled"/> without doing any work.</para>
/// <para>A deterministic Block needs no AI call (<see cref="AiAnalysisStatus.NotNeeded"/>) and touches neither the
/// circuit breaker nor the capacity gate. Otherwise the call needs a circuit permit (<see cref="AiAnalysisStatus.CircuitOpen"/>
/// if refused) and then capacity admission, including the input-token reservation
/// (<see cref="AiAnalysisStatus.CapacityExceeded"/> if refused); both refusals hold the input for review, so neither an
/// exhausted budget nor a failing provider switches the AI layer off (docs/security/ai-analysis.md, sections 16–17).
/// The circuit is asked first so that an open circuit consumes no capacity. Permit and admission are released when the
/// call has ended, however it ended.</para>
/// <para>Scoped, because a provider adapter built on a typed <c>HttpClient</c> is transient and must not be captured by
/// a singleton.</para>
/// </remarks>
internal sealed class AiAssistedAnalysis(
    IAiDisclosurePolicy disclosurePolicy,
    IRiskEngine riskEngine,
    IPolicyEngine policyEngine,
    IAiCapacityGate capacityGate,
    IAiCircuitBreaker circuitBreaker,
    ICallerContext callerContext,
    TimeProvider timeProvider,
    IAiSecurityAnalyzer? analyzer = null) : IAiAssistedAnalysis, IScopedService
{
    public async Task<AiAnalysisOutcome> AnalyzeAsync(
        NormalizedInput input,
        IReadOnlyList<ThreatFinding> deterministicFindings,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(input);
        ArgumentNullException.ThrowIfNull(deterministicFindings);

        if (analyzer is null)
        {
            return AiAnalysisOutcome.Disabled;
        }

        cancellationToken.ThrowIfCancellationRequested();
        var started = timeProvider.GetTimestamp();

        // AI findings are only ever added to the deterministic ones, and the risk level is the highest severity, so the
        // final decision can never be below this one. The real risk and policy engines say what it is: the stage has no
        // threshold of its own.
        var deterministicDecision = policyEngine.Decide(riskEngine.Assess(deterministicFindings), deterministicFindings).Decision;

        // Only a deterministic Block may skip the AI: nothing the AI adds can change it. The gate decides whether a Block
        // skips (configuration); a "not needed" for any other decision is a faulty gate and holds the input for review,
        // so the gate alone can never leave an input the AI was expected to analyse at the deterministic decision.
        var skipAllowed = deterministicDecision == SecurityDecision.Block;

        // 1. A deterministic Block needs no AI call: no disclosure work, no circuit breaker, no capacity.
        if (!capacityGate.IsCallNeeded(deterministicDecision))
        {
            return skipAllowed ? NotNeeded(started) : Failed(AiAnalysisStatus.CapacityExceeded, started);
        }

        // 2. What would be sent, and a conservative upper bound on its input tokens (local; never a provider request).
        var disclosure = disclosurePolicy.Prepare(input);
        if (disclosure.Content is not { } content)
        {
            return Failed(AiAnalysisStatus.ContentWithheld, started);
        }

        var request = new AiAnalysisRequest(
            content,
            [.. deterministicFindings.Select(finding => new AiContextFinding(finding.Category, finding.Code, finding.Severity))]);
        var estimatedInputTokens = AiInputTokenEstimate.For(request, analyzer);

        // 3. The circuit breaker before the capacity gate, so an open circuit refuses without consuming any budget. A
        //    permit disposed without a report (capacity refused, cancellation, exception) frees a half-open probe slot.
        using var permit = circuitBreaker.TryAcquire();
        if (!permit.IsAllowed)
        {
            return Failed(AiAnalysisStatus.CircuitOpen, started);
        }

        // 4. Capacity: requests, input tokens, concurrency. Released when this method ends: after the answer, a failure,
        //    the timeout, cancellation or an exception.
        using var admission = capacityGate.TryAdmit(new AiAdmissionRequest(callerContext.ClientId, deterministicDecision, estimatedInputTokens));
        if (admission.Status == AiAdmissionStatus.NotNeeded && skipAllowed)
        {
            return NotNeeded(started);
        }

        // Every refusal (and any status this stage does not know) holds the input for review; it never falls back to
        // the deterministic decision alone.
        if (admission.Status != AiAdmissionStatus.Admitted)
        {
            return Failed(AiAnalysisStatus.CapacityExceeded, started);
        }

        // 5. The provider call: exactly one attempt, bounded by the stage timeout (or the probe's tighter one).
        var callTimeout = permit.CallTimeout is { } probeTimeout && probeTimeout < AiAnalysisLimits.Timeout ? probeTimeout : AiAnalysisLimits.Timeout;
        Result<AiAnalysisOutput> response;
        using (var timeout = new CancellationTokenSource(callTimeout, timeProvider))
        using (var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, timeout.Token))
        {
            try
            {
                // WaitAsync bounds the wait even if the adapter ignores the token; an abandoned call's result is never
                // read.
                response = await analyzer.AnalyzeAsync(request, linked.Token).WaitAsync(linked.Token);
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
            {
                permit.Report(AiAnalysisStatus.TimedOut);
                return Failed(AiAnalysisStatus.TimedOut, started);
            }
        }

        // 6. The circuit learns only the normalised outcome: availability failure, or "the provider answered".
        var callStatus = response.IsFailure ? StatusFor(response.Error) : AiAnalysisStatus.Completed;
        permit.Report(callStatus);
        if (response.IsFailure)
        {
            return Failed(callStatus, started);
        }

        var validated = AiResponseValidator.Validate(response.Value, analyzer.Provider);
        if (validated.IsFailure)
        {
            return Failed(AiAnalysisStatus.InvalidResponse, started, validated.Error.Metadata[AiResponseValidator.ViolationKey] as string);
        }

        var findings = validated.Value;
        return new AiAnalysisOutcome(
            new AiAnalysisSummary(AiAnalysisStatus.Completed, analyzer.Provider, analyzer.Model, findings.Count, Elapsed(started)),
            findings);
    }

    /// <summary>Maps an adapter's error to a status. A code the stage does not know is not assumed to be harmless.</summary>
    internal static AiAnalysisStatus StatusFor(Error error) => error.Code switch
    {
        AiAnalysisErrors.TimeoutCode => AiAnalysisStatus.TimedOut,
        AiAnalysisErrors.UnavailableCode => AiAnalysisStatus.Unavailable,
        AiAnalysisErrors.RateLimitedCode => AiAnalysisStatus.RateLimited,
        AiAnalysisErrors.NetworkFailureCode => AiAnalysisStatus.NetworkFailure,
        AiAnalysisErrors.MalformedResponseCode => AiAnalysisStatus.MalformedResponse,
        AiAnalysisErrors.RefusedCode => AiAnalysisStatus.Refused,

        // Explicit, not left to the default: a rejected request may be content-induced, so it holds for review.
        AiAnalysisErrors.RequestRejectedCode => AiAnalysisStatus.UnclassifiedFailure,
        _ => AiAnalysisStatus.UnclassifiedFailure,
    };

    private AiAnalysisOutcome Failed(AiAnalysisStatus status, long started, string? violation = null)
    {
        var summary = new AiAnalysisSummary(status, analyzer!.Provider, analyzer.Model, 0, Elapsed(started));

        // The table has one handling (Review); asking it still rejects a status that is not a failure.
        return AiFailurePolicy.For(status) == AiFailureHandling.Review
            ? new AiAnalysisOutcome(summary, [AiFindingCatalog.Incomplete(status, violation)])
            : throw new InvalidOperationException("Unknown AI failure handling.");
    }

    private AiAnalysisOutcome NotNeeded(long started) => new(
        new AiAnalysisSummary(AiAnalysisStatus.NotNeeded, analyzer!.Provider, analyzer.Model, 0, Elapsed(started)),
        []);

    private TimeSpan Elapsed(long started) => timeProvider.GetElapsedTime(started);
}
