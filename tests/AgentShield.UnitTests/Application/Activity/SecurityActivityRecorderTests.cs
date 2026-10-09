using AgentShield.Application.Abstractions.Activity;
using AgentShield.Application.Activity;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Threats;
using static AgentShield.UnitTests.Application.Activity.ActivityTestEvents;

namespace AgentShield.UnitTests.Application.Activity;

public class SecurityActivityRecorderTests
{
    [Fact]
    public async Task PublishAsync_AppendsTheEventsActivityRecord()
    {
        var store = new RecordingStore();
        var securityEvent = Event(SecurityDecision.Block, 75, findings: [Finding("InstructionOverride.IgnorePrevious", ThreatCategory.InstructionOverride, ThreatSeverity.High)]);

        await new SecurityActivityRecorder(store).PublishAsync(securityEvent, CancellationToken.None);

        Assert.Equal(SecurityActivityRecord.FromSecurityEvent(securityEvent), Assert.Single(store.Appended), RecordComparer.Instance);
    }

    [Fact]
    public async Task PublishAsync_StoreFails_TheFailureIsNotSwallowed()
    {
        var store = new RecordingStore { Failure = new InvalidOperationException("store fault") };

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new SecurityActivityRecorder(store).PublishAsync(Event(SecurityDecision.Block, 90), CancellationToken.None).AsTask());

        Assert.Same(store.Failure, thrown);
    }

    private sealed class RecordingStore : ISecurityActivityStore
    {
        public List<SecurityActivityRecord> Appended { get; } = [];

        public Exception? Failure { get; init; }

        public ValueTask AppendAsync(SecurityActivityRecord record, CancellationToken cancellationToken)
        {
            if (Failure is not null)
            {
                return ValueTask.FromException(Failure);
            }

            Appended.Add(record);
            return ValueTask.CompletedTask;
        }

        public ValueTask<SecurityActivitySlice> QueryAsync(SecurityActivityQuery query, CancellationToken cancellationToken) =>
            throw new NotSupportedException();
    }

    /// <summary>Field by field, with the findings compared by content (records compare lists by reference).</summary>
    private sealed class RecordComparer : IEqualityComparer<SecurityActivityRecord>
    {
        public static RecordComparer Instance { get; } = new();

        public bool Equals(SecurityActivityRecord? x, SecurityActivityRecord? y) =>
            x is not null && y is not null
            && (x.SecurityEventId, x.CorrelationId, x.OccurredAt, x.Kind, x.Decision, x.Risk, x.AiAnalysis, x.AgentAction)
                == (y.SecurityEventId, y.CorrelationId, y.OccurredAt, y.Kind, y.Decision, y.Risk, y.AiAnalysis, y.AgentAction)
            && x.Findings.SequenceEqual(y.Findings);

        public int GetHashCode(SecurityActivityRecord obj) => obj.SecurityEventId.GetHashCode();
    }
}
