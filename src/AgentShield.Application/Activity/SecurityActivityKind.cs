namespace AgentShield.Application.Activity;

/// <summary>
/// What a security activity record is about. Each kind has its own pipeline that produces a decided security event first;
/// the history then records it, metadata only. Later kinds (for example a tool's result) are added here when the pipeline
/// that decides them exists.
/// </summary>
/// <remarks>
/// There is deliberately no kind per decision (an "allowed" or "blocked" agent action): the record's decision says that,
/// and a kind that restated it could disagree with it.
/// </remarks>
public enum SecurityActivityKind
{
    /// <summary>An input analysed by the firewall (<c>POST /api/v1/firewall/analyze</c>).</summary>
    InputAnalysis = 1,

    /// <summary>An agent's proposed tool action decided by the authorization boundary
    /// (<c>POST /api/v1/agent/actions/authorize</c>). Nothing was executed.</summary>
    AgentActionAuthorization = 2,

    /// <summary>A tool execution request through the tool gateway (<c>POST /api/v1/agent/tools/execute</c>): the decision,
    /// and whether the tool ran. One record per request, from its last audit entry.</summary>
    ToolExecution = 3,
}
