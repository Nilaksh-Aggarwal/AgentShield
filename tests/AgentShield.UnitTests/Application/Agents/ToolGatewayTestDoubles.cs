using System.Collections.Concurrent;
using System.Text.Json;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.Context;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Domain.Risk;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.UnitTests.Application.Agents;

internal sealed class FixedCaller(string clientId) : ICallerContext
{
    public string ClientId { get; } = clientId;
}

internal sealed class FixedCorrelation(string correlationId) : ICorrelationContext
{
    public string CorrelationId { get; } = correlationId;
}

/// <summary>Agent profiles looked up by ID or by gateway client, optionally answering for any client (a lenient lookup).</summary>
internal sealed class GatewayDirectory(AgentProfile[] profiles, bool lenient = false) : IAgentDirectory
{
    public AgentProfile? Find(AgentId agent) => profiles.SingleOrDefault(profile => profile.Id == agent);

    public AgentProfile? FindByGatewayClient(string clientId) =>
        lenient ? profiles.FirstOrDefault() : profiles.SingleOrDefault(profile => profile.GatewayClient == clientId);
}

/// <summary>Returns one verdict, recording every request it was asked about.</summary>
internal sealed class ScriptedAuthorizer(AgentActionAuthorization verdict) : IAgentActionAuthorizer
{
    public ConcurrentQueue<AgentActionRequest> Received { get; } = new();

    public AgentActionAuthorization Verdict { get; set; } = verdict;

    public AgentActionAuthorization Authorize(AgentActionRequest request)
    {
        Received.Enqueue(request);
        return Verdict;
    }

    public static AgentActionAuthorization For(AgentActionReason reason, RiskLevel risk) =>
        new(reason, risk, new RecognisedAgentAction(new AgentId("support-agent"), new ToolId("knowledge"), new ActionName("lookup"), new Capability("knowledge:read")));
}

/// <summary>An argument policy for one action that accepts or rejects, recording what it was given.</summary>
internal sealed class ScriptedArgumentPolicy(string tool, string action, ToolArgumentViolation? rejectWith = null) : IToolArgumentPolicy
{
    public ToolId Tool { get; } = new(tool);

    public ActionName Action { get; } = new(action);

    public int Checks { get; private set; }

    public ToolArgumentCheck Check(JsonElement arguments)
    {
        Checks++;
        return rejectWith is { } violation
            ? ToolArgumentCheck.Reject(violation)
            : ToolArgumentCheck.Accept(new KnowledgeLookupArguments("dependency injection"));
    }
}

/// <summary>
/// An execution authority whose answers are scripted: issues a grant (or refuses), then runs the call (returns an output,
/// refuses the grant, or throws), recording every call.
/// </summary>
internal sealed class ScriptedExecutionAuthority : IToolExecutionAuthority
{
    public bool IssueNothing { get; set; }

    public ExecutionGrantRejection? RefuseWith { get; set; }

    public Exception? ThrowOnExecute { get; set; }

    public ToolOutput Output { get; set; } = new(found: true, "Dependency injection: the composition root chooses.");

    public List<(AgentActionRequest Request, SecurityEventId SecurityEventId, string CorrelationId, Guid? ApprovalId)> Issued { get; } = [];

    public List<ExecutionGrant> Grants { get; } = [];

    public List<(ExecutionGrant Grant, ToolCall Call)> Executions { get; } = [];

    public ExecutionGrant? Issue(AgentActionRequest request, SecurityEventId securityEventId, string correlationId, Guid? approvalId = null)
    {
        Issued.Add((request, securityEventId, correlationId, approvalId));
        if (IssueNothing)
        {
            return null;
        }

        var issuedAt = DateTimeOffset.UnixEpoch.AddYears(56);
        var grant = new ExecutionGrant(
            Guid.CreateVersion7(),
            new ExecutionScope(securityEventId, correlationId, request.Agent, request.Tool, request.Action, request.Capability),
            issuedAt,
            issuedAt.AddSeconds(30),
            "scripted-signature");
        Grants.Add(grant);
        return grant;
    }

    public ValueTask<ToolExecutionAttempt> ExecuteAsync(ExecutionGrant grant, ToolCall call, CancellationToken cancellationToken)
    {
        Executions.Add((grant, call));
        if (ThrowOnExecute is { } failure)
        {
            return ValueTask.FromException<ToolExecutionAttempt>(failure);
        }

        return ValueTask.FromResult(RefuseWith is { } rejection ? ToolExecutionAttempt.Refused(rejection) : ToolExecutionAttempt.Ran(Output));
    }
}

/// <summary>Records every entry it is given, in order; optionally fails on one stage.</summary>
internal sealed class RecordingGatewaySink(ToolGatewayEventType? failOn = null, Exception? failure = null) : IToolGatewayEventSink
{
    public List<ToolGatewayEvent> Entries { get; } = [];

    public IEnumerable<ToolGatewayEventType> Types => Entries.Select(entry => entry.Type);

    public ValueTask PublishAsync(ToolGatewayEvent toolGatewayEvent, CancellationToken cancellationToken)
    {
        Entries.Add(toolGatewayEvent);
        return toolGatewayEvent.Type == failOn
            ? ValueTask.FromException(failure ?? new InvalidOperationException("Sink failure (test)."))
            : ValueTask.CompletedTask;
    }
}
