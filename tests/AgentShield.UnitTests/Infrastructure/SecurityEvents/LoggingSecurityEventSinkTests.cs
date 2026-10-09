using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Infrastructure.SecurityEvents;
using AgentShield.UnitTests.Infrastructure.AiCapacity;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentShield.UnitTests.Infrastructure.SecurityEvents;

/// <summary>The security-event sink's decision count, which does not depend on the audit log being written.</summary>
public sealed class LoggingSecurityEventSinkTests : IDisposable
{
    private readonly TestMeterFactory _meters = new();

    public void Dispose() => _meters.Dispose();

    [Fact]
    public async Task PublishAsync_CountsEveryDecision_EvenWhenTheAuditLogLevelIsDisabled()
    {
        // H-07: the audit entry is skipped when its log level is disabled, and Serilog swallows sink failures. The decision
        // count does not go through logging, so a gap between decisions and audit entries is visible to operators.
        using var decisions = _meters.Record(LoggingSecurityEventSink.DecisionsInstrument, LoggingSecurityEventSink.DecisionTag);
        var sink = new LoggingSecurityEventSink(NullLogger<LoggingSecurityEventSink>.Instance, _meters);

        foreach (var decision in new[] { SecurityDecision.Allow, SecurityDecision.Review, SecurityDecision.Block, SecurityDecision.Block })
        {
            await sink.PublishAsync(Event(decision), CancellationToken.None);
        }

        Assert.Equal(new Dictionary<string, int> { ["Allow"] = 1, ["Review"] = 1, ["Block"] = 2 }, decisions.CountsByTag());
        Assert.Equal([LoggingSecurityEventSink.DecisionTag], decisions.TagKeys());
    }

    private static SecurityEvent Event(SecurityDecision decision) => new(
        SecurityEventId.New(),
        "sink-test",
        DateTimeOffset.UnixEpoch,
        new PolicyDecision(decision, "Policy.Test", "Test decision."),
        RiskAssessment.None,
        [],
        5,
        TimeSpan.FromMilliseconds(1));
}
