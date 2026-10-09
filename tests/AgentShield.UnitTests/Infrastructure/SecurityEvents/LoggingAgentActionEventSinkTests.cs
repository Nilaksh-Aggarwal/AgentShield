using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Infrastructure.SecurityEvents;
using AgentShield.UnitTests.Infrastructure.AiCapacity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentShield.UnitTests.Infrastructure.SecurityEvents;

/// <summary>The audit log of agent action authorizations: one entry per decision, recognised names only, always counted.</summary>
public sealed class LoggingAgentActionEventSinkTests : IDisposable
{
    private readonly TestMeterFactory _meters = new();

    public void Dispose() => _meters.Dispose();

    [Theory]
    [InlineData(AgentActionReason.Permitted, LogLevel.Information)]
    [InlineData(AgentActionReason.HumanApprovalRequired, LogLevel.Warning)]
    [InlineData(AgentActionReason.InputHeldForReview, LogLevel.Warning)]
    [InlineData(AgentActionReason.CapabilityNotGranted, LogLevel.Warning)]
    [InlineData(AgentActionReason.CriticalActionDenied, LogLevel.Warning)]
    public async Task PublishAsync_LogsOneEntry_AllowAtInformation_ReviewAndBlockAtWarning(AgentActionReason reason, LogLevel level)
    {
        var logger = new RecordingLogger<LoggingAgentActionEventSink>();
        var agentActionEvent = Event(new AgentActionAuthorization(reason, RiskLevel.High, Complete()), SecurityDecision.Review);

        await new LoggingAgentActionEventSink(logger, _meters).PublishAsync(agentActionEvent, CancellationToken.None);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(level, entry.Level);
        Assert.Equal(1001, entry.EventId.Id);
        Assert.Equal(agentActionEvent.Id.Value.ToString(), entry.Properties["SecurityEventId"]);
        Assert.Equal("corr-audit", entry.Properties["CorrelationId"]);
        Assert.Equal(AgentActionReasons.DecisionFor(reason).ToString(), entry.Properties["Decision"]);
        Assert.Equal(reason.ToString(), entry.Properties["AgentActionReason"]);
        Assert.Equal("High", entry.Properties["RiskLevel"]);
        Assert.Equal(("support-agent", "email", "send", "email:send"), (entry.Properties["AgentId"], entry.Properties["Tool"], entry.Properties["ToolAction"], entry.Properties["Capability"]));
        Assert.Equal("Review", entry.Properties["InputDecision"]);
    }

    [Fact]
    public async Task PublishAsync_UnrecognisedNames_AreLoggedAsUnknown_NeverVerbatim()
    {
        var logger = new RecordingLogger<LoggingAgentActionEventSink>();
        var authorization = new AgentActionAuthorization(AgentActionReason.UnknownAgent, RiskLevel.Critical, new RecognisedAgentAction(null, null, null, null));

        await new LoggingAgentActionEventSink(logger, _meters).PublishAsync(Event(authorization, null), CancellationToken.None);

        var entry = Assert.Single(logger.Entries);
        Assert.All(["AgentId", "Tool", "ToolAction", "Capability"], name => Assert.Equal(LoggingAgentActionEventSink.Unknown, entry.Properties[name]));
        Assert.Equal("(none)", entry.Properties["InputDecision"]);
    }

    [Fact]
    public async Task PublishAsync_CountsEveryDecision_EvenWhenTheAuditLogLevelIsDisabled()
    {
        using var decisions = _meters.Record(LoggingAgentActionEventSink.DecisionsInstrument, LoggingSecurityEventSink.DecisionTag);
        var sink = new LoggingAgentActionEventSink(NullLogger<LoggingAgentActionEventSink>.Instance, _meters);

        (AgentActionReason Reason, RecognisedAgentAction Recognised)[] verdicts =
        [
            (AgentActionReason.Permitted, Complete()),
            (AgentActionReason.HumanApprovalRequired, Complete()),
            (AgentActionReason.UnknownTool, new RecognisedAgentAction(new AgentId("support-agent"), null, null, null)),
            (AgentActionReason.CapabilityMismatch, Complete()),
        ];
        foreach (var (reason, recognised) in verdicts)
        {
            await sink.PublishAsync(Event(new AgentActionAuthorization(reason, RiskLevel.Low, recognised), null), CancellationToken.None);
        }

        Assert.Equal(new Dictionary<string, int> { ["Allow"] = 1, ["Review"] = 1, ["Block"] = 2 }, decisions.CountsByTag());
        Assert.Equal([LoggingSecurityEventSink.DecisionTag], decisions.TagKeys());
    }

    private static RecognisedAgentAction Complete() =>
        new(new AgentId("support-agent"), new ToolId("email"), new ActionName("send"), new Capability("email:send"));

    private static AgentActionEvent Event(AgentActionAuthorization authorization, SecurityDecision? inputDecision) =>
        new(SecurityEventId.New(), "corr-audit", DateTimeOffset.UnixEpoch, authorization, inputDecision, TimeSpan.FromMilliseconds(1));
}
