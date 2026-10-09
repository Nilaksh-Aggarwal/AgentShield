namespace AgentShield.Api.Auth;

/// <summary>
/// Permissions an API client can hold, carried as <see cref="ClaimType"/> claims on the authenticated principal.
/// Authorization policies (<see cref="AuthorizationPolicies"/>) require permissions, never client IDs or schemes, so a
/// future identity provider only has to issue the same claims.
/// </summary>
public static class Permissions
{
    /// <summary>Claim type of a permission.</summary>
    public const string ClaimType = "permission";

    /// <summary>Submit input to the firewall analysis endpoint.</summary>
    public const string FirewallAnalyze = "firewall:analyze";

    /// <summary>
    /// Read the security activity history: metadata of every client's analyses. An operator permission, deliberately
    /// separate from <see cref="FirewallAnalyze"/>, so an application that submits inputs cannot read other activity.
    /// </summary>
    public const string ActivityRead = "activity:read";

    /// <summary>
    /// Ask the agent action authorization boundary whether an agent may perform a tool action
    /// (<c>POST /api/v1/agent/actions/authorize</c>). For the runtime that executes an agent's tool calls. Separate from
    /// <see cref="FirewallAnalyze"/> (screening input) and <see cref="ActivityRead"/> (reading every client's history):
    /// it grants neither, and neither grants it.
    /// </summary>
    public const string AgentAuthorize = "agent:authorize";

    /// <summary>
    /// Execute a tool action through the tool gateway (<c>POST /api/v1/agent/tools/execute</c>). For an agent's own
    /// credential: a client holding it must be the gateway identity of exactly one agent
    /// (<c>AgentAuthorization:Agents:{agentId}:GatewayClient</c>), and acts as that agent only. Separate from every other
    /// permission: it grants none of them, and none of them grants it.
    /// </summary>
    public const string ToolExecute = "tool:execute";

    /// <summary>
    /// Approve or deny a tool call the gateway held for review, and list approvals (<c>/api/v1/agent/approvals</c>). For a
    /// person's console, never an agent: outside Development a client holding it may hold neither <see cref="ToolExecute"/>
    /// nor <see cref="AgentAuthorize"/> (startup validation), so no agent can approve its own calls. It grants nothing else,
    /// and nothing else grants it.
    /// </summary>
    public const string AgentApprove = "agent:approve";

    /// <summary>Every permission that exists; configuration naming anything else fails at startup.</summary>
    public static readonly IReadOnlySet<string> All = new HashSet<string>(StringComparer.Ordinal) { FirewallAnalyze, ActivityRead, AgentAuthorize, ToolExecute, AgentApprove };
}
