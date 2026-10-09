using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Domain.Policy;
using AgentShield.Infrastructure.AiCapacity;
using Microsoft.Extensions.Options;
using static AgentShield.UnitTests.Infrastructure.AiCapacity.InMemoryAiCapacityGateTests;

namespace AgentShield.UnitTests.Infrastructure.AiCapacity;

/// <summary>
/// The gate's rolling per-minute input-token budget (Milestone 6 step 2): global and per-client limits, guarantees,
/// oversized requests, reservation semantics and metrics. The committed defaults: 200,000 per minute globally, 40,000
/// guaranteed and 80,000 at most per client.
/// </summary>
public sealed class AiInputTokenBudgetTests : IDisposable
{
    private const string A = "client-a";
    private const string B = "client-b";

    private readonly ManualClock _clock = new();
    private readonly TestMeterFactory _meters = new();
    private readonly RecordingLogger<InMemoryAiCapacityGate> _logger = new();

    public void Dispose() => _meters.Dispose();

    [Fact]
    public void TryAdmit_GlobalTokenBudget_AdmitsUpToTheLimit_ThenRefusesEveryClient()
    {
        string[] clients = ["c1", "c2", "c3", "c4", "c5"];
        var gate = Gate(clients: clients);

        Assert.All(clients, client => Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, client, 40_000)));

        Assert.All(clients, client => Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, client, 1)));
        Assert.Contains(_logger.Entries, entry => entry.Properties["CapacityLimit"] == "GlobalInputTokensPerMinute");
    }

    [Fact]
    public void TryAdmit_ClientTokenMaximum_IsEnforced_WhileGlobalTokensRemain()
    {
        var gate = Gate();

        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A, 40_000));
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A, 40_000));
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A, 1));

        Assert.Equal("ClientInputTokensPerMinute", Assert.Single(_logger.Entries).Properties["CapacityLimit"]);
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, B, 40_000));
    }

    [Theory]
    [InlineData(80_001)]
    [InlineData(96_000)]
    [InlineData(1_000_000)]
    public void TryAdmit_RequestLargerThanTheClientMaximum_IsNeverAdmitted_AndConsumesNothing(long estimate)
    {
        // 96,000 is the floor of a maximal (32,000-character) CJK input: too large to send, so it is held for review.
        var gate = Gate();

        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A, estimate));
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A, estimate));

        // Nothing was reserved: all four request slots (the client maximum) and the tokens are still there.
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A, 20_000));
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A, 20_000));
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A, 20_000));
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A, 20_000));
    }

    [Theory]
    [InlineData(long.MaxValue)]
    [InlineData(long.MaxValue - 499)]
    public void TryAdmit_AbsurdEstimateAfterEarlierReservations_IsRefused_NotOverflowedIntoAnAdmission(long estimate)
    {
        // The estimate is whatever the adapter reports (the stage only raises it to its floor): a faulty adapter could
        // report any long. Adding it to what the client already reserved must not wrap round and pass the limits.
        var gate = Gate();
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A, 500));

        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A, estimate));
        Assert.Equal("ClientInputTokensPerMinute", Assert.Single(_logger.Entries).Properties["CapacityLimit"]);

        // Nothing was reserved: exactly the rest of the client's 80,000 fits, and not one token more.
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A, 79_500));
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A, 1));
    }

    [Fact]
    public void TryAdmit_TokenGuarantee_OfAClientThatHasNotCalled_IsProtected()
    {
        var gate = Gate(options => (options.DefaultClient!.MaxInputTokensPerMinute, options.DefaultClient.MaxPerMinute) = (200_000, 10));

        // a may take everything but b's 40,000: four calls of 40,000.
        for (var index = 0; index < 4; index++)
        {
            Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A, 40_000));
        }

        _clock.Advance(TimeSpan.FromSeconds(1));
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A, 1));
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, B, 40_000));
    }

    [Fact]
    public void TryAdmit_TokensFreeExactlyOneMinuteAfterAdmission()
    {
        var gate = Gate();
        Call(gate, A, 80_000);

        _clock.Advance(TimeSpan.FromMinutes(1) - TimeSpan.FromTicks(1));
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A, 1));

        _clock.Advance(TimeSpan.FromTicks(1));
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A, 80_000));
    }

    [Fact]
    public void Admission_ReleasedAfterAFailedCall_KeepsItsTokenReservation_ButReturnsTheConcurrencySlot()
    {
        // A call that was sent may have been counted by the provider, whatever its outcome: no refund.
        var gate = Gate();
        using (gate.TryAdmit(Request(A, inputTokens: 40_000)))
        {
            Assert.Equal(1, gate.InFlight);
        }

        using (gate.TryAdmit(Request(A, inputTokens: 40_000)))
        {
        }

        Assert.Equal(0, gate.InFlight);
        Assert.Equal(AiAdmissionStatus.CapacityExceeded, Call(gate, A, 1));
    }

    [Fact]
    public void TryAdmit_RefusedForAnyReason_ReservesNoTokens()
    {
        var gate = Gate(options => options.DefaultClient!.MaxConcurrentCalls = 1);
        using var held = gate.TryAdmit(Request(A, inputTokens: 1_000));

        // Refused for concurrency ten times over with large estimates: nothing reserved.
        for (var index = 0; index < 10; index++)
        {
            Assert.Equal(AiAdmissionStatus.ConcurrencyExceeded, Call(gate, A, 70_000));
        }

        held.Dispose();
        Assert.Equal(AiAdmissionStatus.Admitted, Call(gate, A, 79_000));
    }

    [Fact]
    public void TryAdmit_NegativeEstimate_IsABug()
    {
        var gate = Gate();

        Assert.Throws<ArgumentOutOfRangeException>(() => gate.TryAdmit(new AiAdmissionRequest(A, SecurityDecision.Allow, -1)));
    }

    [Fact]
    public void TokenMetrics_CountAcceptedAndRejectedReservations_AndTheReservedAmount_WithBoundedTags()
    {
        using var admissions = _meters.Record(InMemoryAiCapacityGate.TokenAdmissionsInstrument, InMemoryAiCapacityGate.ResultTag);
        using var reserved = _meters.Record(InMemoryAiCapacityGate.ReservedInputTokensInstrument, "none");
        var gate = Gate();

        Call(gate, A, 300);
        Call(gate, A, 200);
        Call(gate, A, 100_000);
        Call(gate, "unknown-client", 10);

        Assert.Equal(new Dictionary<string, int> { ["accepted"] = 2, ["rejected"] = 1 }, admissions.CountsByTag());
        Assert.Equal(500, reserved.CountsByTag()["(none)"]);
        Assert.Equal([InMemoryAiCapacityGate.ResultTag], admissions.TagKeys());
        Assert.Empty(reserved.TagKeys());
    }

    [Fact]
    public void TokenMetrics_RefusalsForOtherReasons_AreNotCountedAsTokenRejections()
    {
        // Only a refusal by a token limit is a token rejection. (Mutation testing: counting an unknown-client refusal instead
        // of a token refusal gave the same totals in the test above.)
        using var admissions = _meters.Record(InMemoryAiCapacityGate.TokenAdmissionsInstrument, InMemoryAiCapacityGate.ResultTag);
        var gate = Gate(options => options.DefaultClient!.MaxConcurrentCalls = 1);
        using var held = gate.TryAdmit(Request(A, inputTokens: 100));
        using var concurrent = gate.TryAdmit(Request(A, inputTokens: 100));
        using var unknown = gate.TryAdmit(Request("unknown-client", inputTokens: 100));

        Assert.Equal((AiAdmissionStatus.ConcurrencyExceeded, AiAdmissionStatus.CapacityExceeded), (concurrent.Status, unknown.Status));
        Assert.Equal(new Dictionary<string, int> { ["accepted"] = 1 }, admissions.CountsByTag());
    }

    [Fact]
    public void Budget_GuaranteesThatOvercommitTheGlobalLimit_NeverAdmitPastIt()
    {
        // Startup validation keeps clients x guarantee within the global limit; the budget still treats the global limit as
        // a hard cap when they do not (mutation testing: this check was never needed by any test).
        var budget = new RequestBudget(window: 60, globalLimit: 10, guaranteed: 8, clientLimit: 10, ["a", "b"]);
        Assert.Equal(BudgetShare.Guaranteed, budget.Check("a", now: 0, amount: 8));
        budget.Record("a", now: 0, amount: 8);

        Assert.Equal(BudgetShare.GlobalLimitReached, budget.Check("b", now: 0, amount: 5));
        Assert.Equal(BudgetShare.Guaranteed, budget.Check("b", now: 0, amount: 2));
    }

    [Fact]
    public void Budget_NegativeAmount_IsABug_EvenWhenTheGateIsBypassed()
    {
        // A negative amount would make room for other calls. The gate refuses it first (TryAdmit_NegativeEstimate_IsABug),
        // so the budget's own guard was never needed by a test (mutation testing).
        var budget = new RequestBudget(window: 60, globalLimit: 10, guaranteed: 5, clientLimit: 10, ["a"]);

        Assert.Throws<ArgumentOutOfRangeException>(() => budget.Check("a", now: 0, amount: -1));
    }

    private InMemoryAiCapacityGate Gate(Action<AiCapacityOptions>? configure = null, string[]? clients = null)
    {
        var options = DefaultOptions();
        configure?.Invoke(options);
        return new InMemoryAiCapacityGate(Options.Create(options), new StaticClientDirectory(clients ?? [A, B]), _clock, _meters, _logger);
    }

    private static AiAdmissionStatus Call(InMemoryAiCapacityGate gate, string clientId, long inputTokens)
    {
        using var admission = gate.TryAdmit(Request(clientId, SecurityDecision.Allow, inputTokens));
        return admission.Status;
    }
}
