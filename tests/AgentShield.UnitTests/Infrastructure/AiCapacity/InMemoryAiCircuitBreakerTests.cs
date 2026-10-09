using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Infrastructure.AiCapacity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AgentShield.UnitTests.Infrastructure.AiCapacity;

/// <summary>
/// The in-memory AI provider circuit breaker on a manual clock: Closed → Open → HalfOpen → Closed/Open, what counts as
/// a failure, one probe at a time, lost and abandoned probes, stale outcomes, metrics and logs.
/// </summary>
public sealed class InMemoryAiCircuitBreakerTests : IDisposable
{
    private static readonly TimeSpan OpenPeriod = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan Tick = TimeSpan.FromTicks(1);

    private readonly ManualClock _clock = new();
    private readonly TestMeterFactory _meters = new();
    private readonly RecordingLogger<InMemoryAiCircuitBreaker> _logger = new();

    public void Dispose() => _meters.Dispose();

    // ── Closed ──────────────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void TryAcquire_Closed_AllowsEveryCall_WithoutProbeOrExtraTimeout()
    {
        var breaker = Breaker();

        var permits = Enumerable.Range(0, 20).Select(_ => breaker.TryAcquire()).ToArray();

        Assert.All(permits, permit => Assert.Equal((true, false, (TimeSpan?)null), (permit.IsAllowed, permit.IsProbe, permit.CallTimeout)));
        Assert.Equal(AiCircuitState.Closed, breaker.State);
    }

    [Theory]
    [InlineData(AiAnalysisStatus.RateLimited)]
    [InlineData(AiAnalysisStatus.Unavailable)]
    [InlineData(AiAnalysisStatus.NetworkFailure)]
    [InlineData(AiAnalysisStatus.TimedOut)]
    public void Report_AvailabilityFailures_OpenTheCircuitAtTheThreshold(AiAnalysisStatus failure)
    {
        var breaker = Breaker();

        Fail(breaker, failure);
        Fail(breaker, failure);
        Assert.Equal(AiCircuitState.Closed, breaker.State);

        Fail(breaker, failure);
        Assert.Equal(AiCircuitState.Open, breaker.State);
        Assert.False(breaker.TryAcquire().IsAllowed);
    }

    [Theory]
    [InlineData(AiAnalysisStatus.UnclassifiedFailure)]
    [InlineData(AiAnalysisStatus.MalformedResponse)]
    [InlineData(AiAnalysisStatus.InvalidResponse)]
    [InlineData(AiAnalysisStatus.Refused)]
    [InlineData(AiAnalysisStatus.Completed)]
    [InlineData(AiAnalysisStatus.ContentWithheld)]
    [InlineData(AiAnalysisStatus.CapacityExceeded)]
    public void Report_OutcomesThatAreNotProviderUnavailability_NeverOpenTheCircuit(AiAnalysisStatus outcome)
    {
        var breaker = Breaker();

        for (var index = 0; index < 50; index++)
        {
            Fail(breaker, outcome);
        }

        Assert.Equal(AiCircuitState.Closed, breaker.State);
    }

    [Fact]
    public void Report_AnyProviderAnswer_ResetsTheConsecutiveFailureCount()
    {
        var breaker = Breaker();

        Fail(breaker, AiAnalysisStatus.RateLimited);
        Fail(breaker, AiAnalysisStatus.Unavailable);
        Fail(breaker, AiAnalysisStatus.UnclassifiedFailure);
        Fail(breaker, AiAnalysisStatus.RateLimited);
        Fail(breaker, AiAnalysisStatus.NetworkFailure);

        Assert.Equal(AiCircuitState.Closed, breaker.State);
    }

    [Fact]
    public void Report_FailuresInterleavedWithOtherCallersSuccesses_NeverOpenTheCircuit()
    {
        // The breaker knows no clients: one caller's failing (e.g. content that stalls the model) calls cannot open the
        // circuit while other calls keep proving the provider reachable.
        var breaker = Breaker();

        for (var index = 0; index < 30; index++)
        {
            Fail(breaker, AiAnalysisStatus.TimedOut);
            Fail(breaker, AiAnalysisStatus.TimedOut);
            Fail(breaker, AiAnalysisStatus.Completed);
        }

        Assert.Equal(AiCircuitState.Closed, breaker.State);
    }

    // ── Open and HalfOpen ───────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void TryAcquire_Open_RefusesUntilTheOpenPeriodEnds_ThenOffersOneProbe()
    {
        var breaker = OpenBreaker();

        _clock.Advance(OpenPeriod - Tick);
        Assert.False(breaker.TryAcquire().IsAllowed);
        Assert.Equal(AiCircuitState.Open, breaker.State);

        _clock.Advance(Tick);
        using var probe = breaker.TryAcquire();

        Assert.Equal((true, true, (TimeSpan?)TimeSpan.FromSeconds(3)), (probe.IsAllowed, probe.IsProbe, probe.CallTimeout));
        Assert.Equal(AiCircuitState.HalfOpen, breaker.State);
    }

    [Fact]
    public void TryAcquire_HalfOpen_AllowsExactlyOneProbe_EveryoneElseIsRefused()
    {
        var breaker = HalfOpenBreaker(out var probe);

        var others = Enumerable.Range(0, 10).Select(_ => breaker.TryAcquire()).ToArray();

        Assert.True(probe.IsProbe);
        Assert.All(others, permit => Assert.False(permit.IsAllowed));
        probe.Dispose();
    }

    [Fact]
    public async Task TryAcquire_HalfOpen_ConcurrentCallers_GetExactlyOneProbe()
    {
        var breaker = OpenBreaker();
        _clock.Advance(OpenPeriod);
        using var start = new ManualResetEventSlim();

        var attempts = Enumerable.Range(0, 64).Select(_ => Task.Run(() =>
        {
            start.Wait(TimeSpan.FromSeconds(10));
            return breaker.TryAcquire();
        })).ToArray();
        start.Set();
        var permits = await Task.WhenAll(attempts).WaitAsync(TimeSpan.FromSeconds(10));

        Assert.Equal(1, permits.Count(permit => permit.IsAllowed));
        Assert.True(Assert.Single(permits, permit => permit.IsAllowed).IsProbe);
    }

    [Theory]
    [InlineData(AiAnalysisStatus.Completed)]
    [InlineData(AiAnalysisStatus.InvalidResponse)]
    [InlineData(AiAnalysisStatus.UnclassifiedFailure)]
    public void Probe_ProviderAnswers_ClosesTheCircuit(AiAnalysisStatus answer)
    {
        var breaker = HalfOpenBreaker(out var probe);

        probe.Report(answer);

        Assert.Equal(AiCircuitState.Closed, breaker.State);
        Assert.All(Enumerable.Range(0, 5).Select(_ => breaker.TryAcquire()), permit => Assert.False(permit.IsProbe || !permit.IsAllowed));
    }

    [Theory]
    [InlineData(AiAnalysisStatus.RateLimited)]
    [InlineData(AiAnalysisStatus.Unavailable)]
    [InlineData(AiAnalysisStatus.NetworkFailure)]
    [InlineData(AiAnalysisStatus.TimedOut)]
    public void Probe_AvailabilityFailure_ReopensForAFullNewPeriod(AiAnalysisStatus failure)
    {
        var breaker = HalfOpenBreaker(out var probe);
        _clock.Advance(TimeSpan.FromSeconds(2));

        probe.Report(failure);

        Assert.Equal(AiCircuitState.Open, breaker.State);
        _clock.Advance(OpenPeriod - Tick);
        Assert.False(breaker.TryAcquire().IsAllowed);
        _clock.Advance(Tick);
        Assert.True(breaker.TryAcquire().IsProbe);
    }

    [Fact]
    public void Probe_ReleasedWithoutAnOutcome_FreesTheSlot_WithoutChangingState()
    {
        // E.g. the probe's caller was refused by the capacity gate: no call was made, nothing was learnt.
        var breaker = HalfOpenBreaker(out var probe);

        probe.Dispose();

        Assert.Equal(AiCircuitState.HalfOpen, breaker.State);
        using var next = breaker.TryAcquire();
        Assert.True(next.IsProbe);
    }

    [Theory]
    [InlineData(AiAnalysisStatus.ContentWithheld)]
    [InlineData(AiAnalysisStatus.CapacityExceeded)]
    [InlineData(AiAnalysisStatus.CircuitOpen)]
    public void Probe_ReportedWithAnOutcomeThatSaysNothingAboutTheProvider_FreesTheSlot_WithoutChangingState(AiAnalysisStatus outcome)
    {
        // Neither an availability failure nor a provider answer: nothing was learnt, as for a released probe (mutation
        // testing: no test reported such an outcome on a probe).
        using var probes = _meters.Record(InMemoryAiCircuitBreaker.ProbesInstrument, "result");
        var breaker = HalfOpenBreaker(out var probe);

        probe.Report(outcome);

        Assert.Equal(AiCircuitState.HalfOpen, breaker.State);
        using var next = breaker.TryAcquire();
        Assert.True(next.IsProbe);
        Assert.Equal(new Dictionary<string, int> { ["started"] = 2, ["abandoned"] = 1 }, probes.CountsByTag());
    }

    [Fact]
    public void Probe_ThatNeverReports_CountsAsFailedAfterItsTimeoutPlusGrace_SoTheCircuitCannotStayHalfOpen()
    {
        var breaker = HalfOpenBreaker(out _);

        _clock.Advance(TimeSpan.FromSeconds(4) - Tick);
        Assert.False(breaker.TryAcquire().IsAllowed);
        Assert.Equal(AiCircuitState.HalfOpen, breaker.State);

        _clock.Advance(Tick);
        Assert.False(breaker.TryAcquire().IsAllowed);
        Assert.Equal(AiCircuitState.Open, breaker.State);

        _clock.Advance(OpenPeriod);
        Assert.True(breaker.TryAcquire().IsProbe);
    }

    [Fact]
    public void Report_FromAnExpiredProbe_IsIgnored()
    {
        var breaker = HalfOpenBreaker(out var lateProbe);
        _clock.Advance(TimeSpan.FromSeconds(4));
        breaker.TryAcquire();

        lateProbe.Report(AiAnalysisStatus.Completed);

        Assert.Equal(AiCircuitState.Open, breaker.State);
    }

    [Fact]
    public void Report_FromCallsStartedBeforeTheCircuitOpened_CannotCloseOrReopenIt()
    {
        var breaker = Breaker();
        var stale = Enumerable.Range(0, 3).Select(_ => breaker.TryAcquire()).ToArray();
        OpenNow(breaker);

        stale[0].Report(AiAnalysisStatus.Completed);
        Assert.Equal(AiCircuitState.Open, breaker.State);

        _clock.Advance(OpenPeriod);
        using var probe = breaker.TryAcquire();
        stale[1].Report(AiAnalysisStatus.Completed);
        stale[2].Report(AiAnalysisStatus.RateLimited);
        Assert.Equal(AiCircuitState.HalfOpen, breaker.State);
    }

    [Fact]
    public void Probe_StaleProbeReport_AfterANewProbeStarted_CannotCloseTheCircuit()
    {
        // Probe 1 is lost (expires), the circuit reopens, its open period elapses and probe 2 starts. Only probe 2 may
        // decide: a late success from probe 1 must not close the circuit (the probe-ID guard).
        var breaker = HalfOpenBreaker(out var staleProbe);
        _clock.Advance(TimeSpan.FromSeconds(4));
        Assert.False(breaker.TryAcquire().IsAllowed);
        _clock.Advance(OpenPeriod);
        using var currentProbe = breaker.TryAcquire();
        Assert.True(currentProbe.IsProbe);

        staleProbe.Report(AiAnalysisStatus.Completed);

        Assert.Equal(AiCircuitState.HalfOpen, breaker.State);
        Assert.False(breaker.TryAcquire().IsAllowed);
    }

    [Fact]
    public void Probe_StaleProbeDispose_AfterANewProbeStarted_DoesNotFreeTheNewProbesSlot()
    {
        // Releasing the lost probe 1 must not free probe 2's slot, or a second probe could run at the same time.
        var breaker = HalfOpenBreaker(out var staleProbe);
        _clock.Advance(TimeSpan.FromSeconds(4));
        Assert.False(breaker.TryAcquire().IsAllowed);
        _clock.Advance(OpenPeriod);
        using var currentProbe = breaker.TryAcquire();
        Assert.True(currentProbe.IsProbe);

        staleProbe.Dispose();

        Assert.False(breaker.TryAcquire().IsAllowed);
    }

    // ── Observability never changes the circuit's accounting (H-05) ─────────────────────────────────────────────────

    [Fact]
    public void Probe_MetricsListenerThrowsWhenTheProbeStarts_TheProbeSlotIsFreed()
    {
        // Regression: the probe slot was taken under the lock and the probe metric recorded before the permit was
        // returned, so a throwing listener left the slot taken until the probe expired (and then reopened the circuit).
        var breaker = OpenBreaker();
        _clock.Advance(OpenPeriod);
        using (_meters.ThrowOn(InMemoryAiCircuitBreaker.ProbesInstrument))
        {
            Assert.Throws<InvalidOperationException>(breaker.TryAcquire);
        }

        using var probe = breaker.TryAcquire();

        Assert.True(probe.IsProbe);
    }

    [Fact]
    public void Probe_MetricsListenerThrowsWhenTheFailureIsCounted_AFailedProbeStillReopensTheCircuit()
    {
        // Regression: the failure metric was recorded before the state change, so a throwing listener kept a failed probe
        // from reopening the circuit.
        var breaker = HalfOpenBreaker(out var probe);
        using (_meters.ThrowOn(InMemoryAiCircuitBreaker.ProviderFailuresInstrument))
        {
            Assert.Throws<InvalidOperationException>(() => probe.Report(AiAnalysisStatus.Unavailable));
        }

        Assert.Equal(AiCircuitState.Open, breaker.State);
    }

    [Fact]
    public void Report_MetricsListenerThrowsWhenTheFailureIsCounted_TheFailureStillCountsTowardsOpening()
    {
        var breaker = Breaker();
        Fail(breaker, AiAnalysisStatus.Unavailable);
        Fail(breaker, AiAnalysisStatus.Unavailable);
        using (_meters.ThrowOn(InMemoryAiCircuitBreaker.ProviderFailuresInstrument))
        {
            Assert.Throws<InvalidOperationException>(() => Fail(breaker, AiAnalysisStatus.Unavailable));
        }

        Assert.Equal(AiCircuitState.Open, breaker.State);
    }

    [Fact]
    public void Probe_MetricsListenerFailsOnceWhenTheProbeStarts_TheCallFails_SoNoSecondProbeCanRun()
    {
        // The slot is given back and the exception still reaches the caller: a permit returned for a freed slot would let a
        // second probe run at the same time (mutation testing: no test reached the rethrow).
        var breaker = OpenBreaker();
        _clock.Advance(OpenPeriod);
        using (_meters.ThrowOn(InMemoryAiCircuitBreaker.ProbesInstrument, times: 1))
        {
            Assert.Throws<InvalidOperationException>(breaker.TryAcquire);
        }

        using var probe = breaker.TryAcquire();

        Assert.True(probe.IsProbe);
        Assert.False(breaker.TryAcquire().IsAllowed);
    }

    [Fact]
    public void Metrics_TagRejectionsByState_ProbesByResult_AndEveryTransitionByTarget()
    {
        using var rejections = _meters.Record(InMemoryAiCircuitBreaker.RejectionsInstrument, "state");
        using var probes = _meters.Record(InMemoryAiCircuitBreaker.ProbesInstrument, "result");
        using var transitions = _meters.Record(InMemoryAiCircuitBreaker.TransitionsInstrument, "to");
        var breaker = OpenBreaker();
        Assert.False(breaker.TryAcquire().IsAllowed); // refused while open
        _clock.Advance(OpenPeriod);
        _ = breaker.TryAcquire(); // a probe starts and is lost
        Assert.False(breaker.TryAcquire().IsAllowed); // refused while half-open
        _clock.Advance(TimeSpan.FromSeconds(4));
        Assert.False(breaker.TryAcquire().IsAllowed); // the lost probe expires: open again, refused
        _clock.Advance(OpenPeriod);
        using (var probe = breaker.TryAcquire())
        {
            probe.Report(AiAnalysisStatus.Completed); // a successful probe closes the circuit
        }

        Assert.Equal(new Dictionary<string, int> { ["open"] = 2, ["half_open"] = 1 }, rejections.CountsByTag());
        Assert.Equal(new Dictionary<string, int> { ["started"] = 2, ["expired"] = 1, ["succeeded"] = 1 }, probes.CountsByTag());
        Assert.Equal(new Dictionary<string, int> { ["open"] = 2, ["half_open"] = 2, ["closed"] = 1 }, transitions.CountsByTag());
    }

    [Fact]
    public void Metrics_EveryProbeHasOneResult_AReleasedProbeIsAbandoned_AndALateReportIsNotCountedAgain()
    {
        // Mutation testing: neither a released probe nor a report arriving after its probe expired was checked against
        // the probe metric.
        using var probes = _meters.Record(InMemoryAiCircuitBreaker.ProbesInstrument, "result");
        var breaker = HalfOpenBreaker(out var released);
        released.Dispose();
        var lost = breaker.TryAcquire();
        Assert.True(lost.IsProbe);
        _clock.Advance(TimeSpan.FromSeconds(4));
        Assert.False(breaker.TryAcquire().IsAllowed); // the lost probe expires: open again

        lost.Report(AiAnalysisStatus.Completed);

        Assert.Equal(AiCircuitState.Open, breaker.State);
        Assert.Equal(new Dictionary<string, int> { ["started"] = 2, ["abandoned"] = 1, ["expired"] = 1 }, probes.CountsByTag());
    }

    [Fact]
    public void Report_FromCallsOfAnEarlierClosedPeriod_AfterTheCircuitClosedAgain_AreIgnored()
    {
        // Three calls start while closed, the circuit opens and closes again, then the three old calls report failures.
        // They belong to the earlier closed period and must not reopen the new one (the closed-generation guard).
        var breaker = Breaker();
        var earlier = Enumerable.Range(0, 3).Select(_ => breaker.TryAcquire()).ToArray();
        OpenNow(breaker);
        _clock.Advance(OpenPeriod);
        using (var probe = breaker.TryAcquire())
        {
            Assert.True(probe.IsProbe);
            probe.Report(AiAnalysisStatus.Completed);
        }

        Assert.Equal(AiCircuitState.Closed, breaker.State);

        foreach (var permit in earlier)
        {
            permit.Report(AiAnalysisStatus.RateLimited);
        }

        Assert.Equal(AiCircuitState.Closed, breaker.State);
        Assert.True(breaker.TryAcquire().IsAllowed);
    }

    [Fact]
    public void Permit_ReportsOnlyOnce()
    {
        var breaker = Breaker();
        var permit = breaker.TryAcquire();
        Fail(breaker, AiAnalysisStatus.RateLimited);
        Fail(breaker, AiAnalysisStatus.RateLimited);

        permit.Report(AiAnalysisStatus.RateLimited);
        permit.Report(AiAnalysisStatus.RateLimited);
        permit.Dispose();

        // Two + one = the threshold exactly; the repeated report on the same permit was not counted a second time.
        Assert.Equal(AiCircuitState.Open, breaker.State);
        var another = Breaker();
        var single = another.TryAcquire();
        single.Report(AiAnalysisStatus.RateLimited);
        single.Report(AiAnalysisStatus.RateLimited);
        single.Report(AiAnalysisStatus.RateLimited);
        Assert.Equal(AiCircuitState.Closed, another.State);
    }

    [Fact]
    public void Disabled_AllowsEveryCall_AndNeverOpens()
    {
        var breaker = Breaker(options => options.Enabled = false);

        for (var index = 0; index < 20; index++)
        {
            Fail(breaker, AiAnalysisStatus.Unavailable);
        }

        Assert.True(breaker.TryAcquire().IsAllowed);
        Assert.Equal(AiCircuitState.Closed, breaker.State);
    }

    // ── Observability ───────────────────────────────────────────────────────────────────────────────────────────────

    [Fact]
    public void Transitions_AreLoggedOncePerTransition_WithStatesAndAFixedReason_AndRejectionsAreNotLogged()
    {
        var breaker = OpenBreaker(AiAnalysisStatus.RateLimited);
        for (var index = 0; index < 100; index++)
        {
            breaker.TryAcquire();
        }

        _clock.Advance(OpenPeriod);
        breaker.TryAcquire().Report(AiAnalysisStatus.Completed);

        Assert.Equal(
            [("Closed", "Open", "RateLimited", LogLevel.Warning), ("Open", "HalfOpen", "OpenPeriodElapsed", LogLevel.Information), ("HalfOpen", "Closed", "ProbeSucceeded", LogLevel.Information)],
            _logger.Entries.Select(entry => (entry.Properties["FromState"], entry.Properties["ToState"], entry.Properties["CircuitReason"], entry.Level)));
        Assert.All(_logger.Entries, entry =>
        {
            Assert.Equal(1300, entry.EventId.Id);
            Assert.Equal(["CircuitReason", "FromState", "ToState", "{OriginalFormat}"], entry.Properties.Keys.Order(StringComparer.Ordinal));
        });
    }

    [Fact]
    public void Transitions_AProbeThatExpires_IsLoggedWithTheReasonProbeExpired()
    {
        // Mutation testing: the reason of this transition was never checked.
        var breaker = HalfOpenBreaker(out _);
        _clock.Advance(TimeSpan.FromSeconds(4));

        Assert.False(breaker.TryAcquire().IsAllowed);

        var reopened = Assert.Single(_logger.Entries, entry => entry.Properties["FromState"] == "HalfOpen" && entry.Properties["ToState"] == "Open");
        Assert.Equal("ProbeExpired", reopened.Properties["CircuitReason"]);
    }

    [Fact]
    public void Metrics_UseOnlyBoundedTagValues()
    {
        using var transitions = _meters.Record(InMemoryAiCircuitBreaker.TransitionsInstrument, "to");
        using var rejections = _meters.Record(InMemoryAiCircuitBreaker.RejectionsInstrument, "state");
        using var probes = _meters.Record(InMemoryAiCircuitBreaker.ProbesInstrument, "result");
        using var failures = _meters.Record(InMemoryAiCircuitBreaker.ProviderFailuresInstrument, "kind");
        var breaker = Breaker();

        Fail(breaker, AiAnalysisStatus.RateLimited);
        Fail(breaker, AiAnalysisStatus.Unavailable);
        Fail(breaker, AiAnalysisStatus.NetworkFailure);
        breaker.TryAcquire();
        _clock.Advance(OpenPeriod);
        var probe = breaker.TryAcquire();
        breaker.TryAcquire();
        probe.Report(AiAnalysisStatus.TimedOut);

        Assert.Equal(new Dictionary<string, int> { ["open"] = 2, ["half_open"] = 1 }, transitions.CountsByTag());
        Assert.Equal(new Dictionary<string, int> { ["open"] = 1, ["half_open"] = 1 }, rejections.CountsByTag());
        Assert.Equal(new Dictionary<string, int> { ["started"] = 1, ["failed"] = 1 }, probes.CountsByTag());
        Assert.Equal(
            new Dictionary<string, int> { ["rate_limited"] = 1, ["unavailable"] = 1, ["network_failure"] = 1, ["timed_out"] = 1 },
            failures.CountsByTag());
        Assert.Equal(["from", "to"], transitions.TagKeys().Order(StringComparer.Ordinal));
        Assert.Equal(["state"], rejections.TagKeys());
        Assert.Equal(["result"], probes.TagKeys());
        Assert.Equal(["kind"], failures.TagKeys());
    }

    // ── Helpers ─────────────────────────────────────────────────────────────────────────────────────────────────────

    /// <summary>The committed defaults: enabled, 3 failures, 30 s open, 3 s probe.</summary>
    internal static AiCircuitBreakerOptions DefaultOptions() => new()
    {
        Enabled = true,
        FailureThreshold = 3,
        OpenDurationSeconds = 30,
        HalfOpenProbeTimeoutSeconds = 3,
    };

    private InMemoryAiCircuitBreaker Breaker(Action<AiCircuitBreakerOptions>? configure = null)
    {
        var options = DefaultOptions();
        configure?.Invoke(options);
        return new InMemoryAiCircuitBreaker(Options.Create(options), _clock, _meters, _logger);
    }

    private static void Fail(InMemoryAiCircuitBreaker breaker, AiAnalysisStatus outcome)
    {
        using var permit = breaker.TryAcquire();
        permit.Report(outcome);
    }

    private static void OpenNow(InMemoryAiCircuitBreaker breaker)
    {
        for (var index = 0; index < 3; index++)
        {
            Fail(breaker, AiAnalysisStatus.Unavailable);
        }

        Assert.Equal(AiCircuitState.Open, breaker.State);
    }

    private InMemoryAiCircuitBreaker OpenBreaker(AiAnalysisStatus failure = AiAnalysisStatus.Unavailable)
    {
        var breaker = Breaker();
        for (var index = 0; index < 3; index++)
        {
            Fail(breaker, failure);
        }

        return breaker;
    }

    private InMemoryAiCircuitBreaker HalfOpenBreaker(out AiCircuitPermit probe)
    {
        var breaker = OpenBreaker();
        _clock.Advance(OpenPeriod);
        probe = breaker.TryAcquire();
        Assert.True(probe.IsProbe);
        return breaker;
    }
}
