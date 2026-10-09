using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Infrastructure.SecurityEvents;
using AgentShield.UnitTests.Infrastructure.AiCapacity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AgentShield.UnitTests.Infrastructure.SecurityEvents;

/// <summary>The tool gateway's audit log: one entry per stage, recognised names only, never content, always counted.</summary>
public sealed class LoggingToolGatewayEventSinkTests : IDisposable
{
    private static readonly DateTimeOffset At = new(2026, 10, 7, 13, 0, 0, TimeSpan.Zero);
    private static readonly Guid ExecutionId = Guid.CreateVersion7();

    private readonly TestMeterFactory _meters = new();

    public void Dispose() => _meters.Dispose();

    [Theory]
    [InlineData(ToolGatewayEventType.ToolAuthorizationRequested, LogLevel.Information)]
    [InlineData(ToolGatewayEventType.ToolAuthorizationAllowed, LogLevel.Information)]
    [InlineData(ToolGatewayEventType.ToolAuthorizationBlocked, LogLevel.Warning)]
    [InlineData(ToolGatewayEventType.ToolAuthorizationReviewed, LogLevel.Warning)]
    [InlineData(ToolGatewayEventType.ToolExecutionStarted, LogLevel.Information)]
    [InlineData(ToolGatewayEventType.ToolExecutionCompleted, LogLevel.Information)]
    [InlineData(ToolGatewayEventType.ToolExecutionRejected, LogLevel.Warning)]
    [InlineData(ToolGatewayEventType.ToolExecutionFailed, LogLevel.Error)]
    public async Task PublishAsync_LogsOneEntryPerStage_AtItsLevel(ToolGatewayEventType type, LogLevel level)
    {
        var logger = new RecordingLogger<LoggingToolGatewayEventSink>();
        var entry = Stage(type);

        await new LoggingToolGatewayEventSink(logger, _meters).PublishAsync(entry, CancellationToken.None);

        var logged = Assert.Single(logger.Entries);
        Assert.Equal((level, 1002, "ToolGatewayEvent"), (logged.Level, logged.EventId.Id, logged.EventId.Name));
        Assert.Equal(type.ToString(), logged.Properties["ToolGatewayStage"]);
        Assert.Equal(entry.Id.Value.ToString(), logged.Properties["SecurityEventId"]);
        Assert.Equal(("corr-audit-gw", "support-agent"), (logged.Properties["CorrelationId"], logged.Properties["AgentId"]));
        Assert.Equal(level, LoggingToolGatewayEventSink.LevelOf(type));
    }

    [Fact]
    public async Task PublishAsync_ARequest_LogsTheAgent_AndEverythingNotDecidedYetAsPending()
    {
        var logger = new RecordingLogger<LoggingToolGatewayEventSink>();

        await new LoggingToolGatewayEventSink(logger, _meters).PublishAsync(Stage(ToolGatewayEventType.ToolAuthorizationRequested), CancellationToken.None);

        var logged = Assert.Single(logger.Entries);
        Assert.All(["Tool", "ToolAction", "Capability", "Decision", "AgentActionReason", "RiskLevel", "ToolExecutionOutcome"],
            name => Assert.Equal(LoggingToolGatewayEventSink.Pending, logged.Properties[name]));
        Assert.All(["ExecutionId", "ArgumentViolation", "GrantRejection"], name => Assert.Equal(LoggingToolGatewayEventSink.None, logged.Properties[name]));
        Assert.Equal("Review", logged.Properties["InputDecision"]);
    }

    [Fact]
    public async Task PublishAsync_ACompletion_LogsTheDecisionOutcomeAndExecution()
    {
        var logger = new RecordingLogger<LoggingToolGatewayEventSink>();

        await new LoggingToolGatewayEventSink(logger, _meters).PublishAsync(Stage(ToolGatewayEventType.ToolExecutionCompleted), CancellationToken.None);

        var logged = Assert.Single(logger.Entries);
        Assert.Equal(("knowledge", "lookup", "knowledge:read"), (logged.Properties["Tool"], logged.Properties["ToolAction"], logged.Properties["Capability"]));
        Assert.Equal(("Allow", "Permitted", "Low", "Executed"), (logged.Properties["Decision"], logged.Properties["AgentActionReason"], logged.Properties["RiskLevel"], logged.Properties["ToolExecutionOutcome"]));
        Assert.Equal(ExecutionId.ToString(), logged.Properties["ExecutionId"]);
    }

    [Fact]
    public async Task PublishAsync_RejectedArgumentsAndGrants_AreLoggedAsCodes()
    {
        var logger = new RecordingLogger<LoggingToolGatewayEventSink>();
        var sink = new LoggingToolGatewayEventSink(logger, _meters);
        var requested = Requested();

        await sink.PublishAsync(requested.Refused(At, TimeSpan.Zero, Verdict(AgentActionReason.Permitted, Complete()), ToolExecutionOutcome.ArgumentsRejected, ToolArgumentViolation.UnexpectedArgument), CancellationToken.None);
        await sink.PublishAsync(requested.Allowed(At, TimeSpan.Zero, Verdict(AgentActionReason.Permitted, Complete()), ExecutionId).Started(At, TimeSpan.Zero).GrantRefused(At, TimeSpan.Zero, ExecutionGrantRejection.AlreadyUsed), CancellationToken.None);

        var entries = logger.Entries.ToArray();
        Assert.Equal(("UnexpectedArgument", "Block", "ArgumentsRejected"), (entries[0].Properties["ArgumentViolation"], entries[0].Properties["Decision"], entries[0].Properties["ToolExecutionOutcome"]));
        Assert.Equal(("AlreadyUsed", "ExecutionAuthorizationRejected"), (entries[1].Properties["GrantRejection"], entries[1].Properties["ToolExecutionOutcome"]));
    }

    [Fact]
    public async Task PublishAsync_UnrecognisedNames_AreLoggedAsUnknown_NeverVerbatim()
    {
        var logger = new RecordingLogger<LoggingToolGatewayEventSink>();
        var unknownTool = Verdict(AgentActionReason.UnknownTool, new RecognisedAgentAction(new AgentId("support-agent"), null, null, null));

        await new LoggingToolGatewayEventSink(logger, _meters).PublishAsync(Requested().Refused(At, TimeSpan.Zero, unknownTool, ToolExecutionOutcome.Denied), CancellationToken.None);

        var logged = Assert.Single(logger.Entries);
        Assert.All(["Tool", "ToolAction", "Capability"], name => Assert.Equal(LoggingToolGatewayEventSink.Unknown, logged.Properties[name]));
        Assert.Equal("UnknownTool", logged.Properties["AgentActionReason"]);
    }

    [Fact]
    public async Task PublishAsync_CountsEveryStage_EvenWhenTheAuditLogLevelIsDisabled()
    {
        using var stages = _meters.Record(LoggingToolGatewayEventSink.EventsInstrument, LoggingToolGatewayEventSink.StageTag);
        var sink = new LoggingToolGatewayEventSink(NullLogger<LoggingToolGatewayEventSink>.Instance, _meters);

        foreach (var type in Enum.GetValues<ToolGatewayEventType>())
        {
            await sink.PublishAsync(Stage(type), CancellationToken.None);
        }

        Assert.Equal(Enum.GetValues<ToolGatewayEventType>().ToDictionary(type => type.ToString(), _ => 1), stages.CountsByTag());
        Assert.Equal([LoggingToolGatewayEventSink.StageTag], stages.TagKeys());
    }

    [Fact]
    public void LevelOf_AnUndefinedStage_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => LoggingToolGatewayEventSink.LevelOf((ToolGatewayEventType)0));
    }

    [Fact]
    public async Task NullDependenciesOrEntry_Throw()
    {
        Assert.Throws<ArgumentNullException>(() => new LoggingToolGatewayEventSink(null!, _meters));
        Assert.Throws<ArgumentNullException>(() => new LoggingToolGatewayEventSink(NullLogger<LoggingToolGatewayEventSink>.Instance, null!));
        var sink = new LoggingToolGatewayEventSink(NullLogger<LoggingToolGatewayEventSink>.Instance, _meters);
        await Assert.ThrowsAsync<ArgumentNullException>(async () => await sink.PublishAsync(null!, CancellationToken.None));
    }

    private static ToolGatewayEvent Stage(ToolGatewayEventType type)
    {
        var requested = Requested();
        var allow = Verdict(AgentActionReason.Permitted, Complete());
        var allowed = requested.Allowed(At, TimeSpan.Zero, allow, ExecutionId);
        var started = allowed.Started(At, TimeSpan.Zero);
        return type switch
        {
            ToolGatewayEventType.ToolAuthorizationRequested => requested,
            ToolGatewayEventType.ToolAuthorizationAllowed => allowed,
            ToolGatewayEventType.ToolAuthorizationBlocked => requested.Refused(At, TimeSpan.Zero, Verdict(AgentActionReason.CapabilityNotGranted, Complete()), ToolExecutionOutcome.Denied),
            ToolGatewayEventType.ToolAuthorizationReviewed => requested.Refused(At, TimeSpan.Zero, Verdict(AgentActionReason.HumanApprovalRequired, Complete()), ToolExecutionOutcome.HeldForReview),
            ToolGatewayEventType.ToolExecutionStarted => started,
            ToolGatewayEventType.ToolExecutionCompleted => started.Completed(At, TimeSpan.Zero),
            ToolGatewayEventType.ToolExecutionRejected => requested.Refused(At, TimeSpan.Zero, Verdict(AgentActionReason.CapabilityNotGranted, Complete()), ToolExecutionOutcome.Denied).Rejected(At, TimeSpan.Zero),
            ToolGatewayEventType.ToolExecutionFailed => started.Failed(At, TimeSpan.Zero),
            _ => throw new ArgumentOutOfRangeException(nameof(type)),
        };
    }

    private static ToolGatewayEvent Requested() =>
        ToolGatewayEvent.Requested(SecurityEventId.New(), "corr-audit-gw", At, new AgentId("support-agent"), SecurityDecision.Review);

    private static AgentActionAuthorization Verdict(AgentActionReason reason, RecognisedAgentAction recognised) =>
        new(reason, reason == AgentActionReason.UnknownTool ? RiskLevel.Critical : RiskLevel.Low, recognised);

    private static RecognisedAgentAction Complete() =>
        new(new AgentId("support-agent"), new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read"));
}
