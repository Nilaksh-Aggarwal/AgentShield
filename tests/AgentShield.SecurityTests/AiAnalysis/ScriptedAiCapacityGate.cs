using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Abstractions.Context;
using AgentShield.Domain.Policy;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Security.AiAnalysis;
using AgentShield.Security.Policy;
using AgentShield.Security.Risk;

namespace AgentShield.SecurityTests.AiAnalysis;

/// <summary>
/// A capacity gate double: answers from a script, records every request and counts admissions and releases. The real
/// gate (budgets, shares, concurrency) is tested in UnitTests; here the stage's use of the gate is under test.
/// </summary>
internal sealed class ScriptedAiCapacityGate(Func<AiAdmissionRequest, AiAdmissionStatus> decide) : IAiCapacityGate
{
    private int _admitted;
    private int _released;

    public List<AiAdmissionRequest> Requests { get; } = [];

    /// <summary>Every deterministic decision the stage asked <see cref="IsCallNeeded"/> about.</summary>
    public List<SecurityDecision> NeededChecks { get; } = [];

    public int Admitted => Volatile.Read(ref _admitted);

    public int Released => Volatile.Read(ref _released);

    /// <summary>Admits every call, including for a deterministic Block (as with SkipWhenDeterministicBlock = false).</summary>
    public static ScriptedAiCapacityGate AdmitAll() => new(_ => AiAdmissionStatus.Admitted);

    /// <summary>The production default: a deterministic Block needs no AI call; everything else is admitted.</summary>
    public static ScriptedAiCapacityGate SkippingBlocks() =>
        new(request => request.DeterministicDecision == SecurityDecision.Block ? AiAdmissionStatus.NotNeeded : AiAdmissionStatus.Admitted);

    public static ScriptedAiCapacityGate Refusing(AiAdmissionStatus status) => new(_ => status);

    /// <summary>The script decides: a call is not needed when the script would answer <see cref="AiAdmissionStatus.NotNeeded"/>.</summary>
    public bool IsCallNeeded(SecurityDecision deterministicDecision)
    {
        NeededChecks.Add(deterministicDecision);
        return decide(new AiAdmissionRequest(string.Empty, deterministicDecision, 0)) != AiAdmissionStatus.NotNeeded;
    }

    public AiAdmission TryAdmit(AiAdmissionRequest request)
    {
        Requests.Add(request);
        switch (decide(request))
        {
            case AiAdmissionStatus.Admitted:
                Interlocked.Increment(ref _admitted);
                return AiAdmission.Admitted(() => Interlocked.Increment(ref _released));
            case AiAdmissionStatus.NotNeeded:
                return AiAdmission.NotNeeded;
            case AiAdmissionStatus.ConcurrencyExceeded:
                return AiAdmission.ConcurrencyExceeded;
            default:
                return AiAdmission.CapacityExceeded;
        }
    }
}

/// <summary>A caller context with a fixed client ID; or one that fails like a request without an authenticated client.</summary>
internal sealed class FixedCallerContext(string? clientId) : ICallerContext
{
    public int Reads { get; private set; }

    public string ClientId
    {
        get
        {
            Reads++;
            return clientId ?? throw new InvalidOperationException("No authenticated API client is in scope.");
        }
    }
}

/// <summary>
/// A circuit breaker double: closed (every call allowed), open (every call refused) or handing out probe permits, and
/// records every reported outcome and abandoned permit. The real breaker is tested in UnitTests.
/// </summary>
internal sealed class ScriptedAiCircuitBreaker : IAiCircuitBreaker
{
    public bool IsOpen { get; set; }

    /// <summary>When set, every permit is a half-open probe with this call timeout.</summary>
    public TimeSpan? ProbeTimeout { get; set; }

    public int Acquired { get; private set; }

    public int Abandoned { get; private set; }

    public List<AiAnalysisStatus> Reports { get; } = [];

    public AiCircuitPermit TryAcquire()
    {
        if (IsOpen)
        {
            return AiCircuitPermit.Rejected;
        }

        Acquired++;
        return ProbeTimeout is { } timeout
            ? AiCircuitPermit.Probe(timeout, Reports.Add, () => Abandoned++)
            : AiCircuitPermit.Allowed(Reports.Add, () => Abandoned++);
    }
}

/// <summary>Builds the AI stage with the real risk and policy engines and test doubles for everything else.</summary>
internal static class AiStages
{
    public const string ClientId = "test-client";

    public static AiAssistedAnalysis Create(
        IAiDisclosurePolicy disclosurePolicy,
        TimeProvider timeProvider,
        IAiSecurityAnalyzer? analyzer,
        IAiCapacityGate? capacityGate = null,
        ICallerContext? callerContext = null,
        IAiCircuitBreaker? circuitBreaker = null) =>
        new(
            disclosurePolicy,
            new SeverityRiskEngine(),
            new RiskThresholdPolicyEngine(),
            capacityGate ?? ScriptedAiCapacityGate.AdmitAll(),
            circuitBreaker ?? new ScriptedAiCircuitBreaker(),
            callerContext ?? new FixedCallerContext(ClientId),
            timeProvider,
            analyzer);
}
