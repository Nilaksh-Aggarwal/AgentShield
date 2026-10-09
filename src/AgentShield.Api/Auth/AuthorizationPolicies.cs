namespace AgentShield.Api.Auth;

/// <summary>
/// Named authorization policies. Endpoints reference a policy by name (<c>[Authorize(Policy = ...)]</c>); what the
/// policy requires is defined once in <see cref="AuthSetup"/>. Endpoints without a policy still require an
/// authenticated client (the fallback policy); anonymous access is an explicit <c>AllowAnonymous</c>.
/// </summary>
public static class AuthorizationPolicies
{
    /// <summary>Requires the <see cref="Permissions.FirewallAnalyze"/> permission.</summary>
    public const string FirewallAnalyze = "FirewallAnalyze";

    /// <summary>Requires the <see cref="Permissions.ActivityRead"/> permission.</summary>
    public const string ActivityRead = "ActivityRead";

    /// <summary>Requires the <see cref="Permissions.AgentAuthorize"/> permission.</summary>
    public const string AgentAuthorize = "AgentAuthorize";

    /// <summary>Requires the <see cref="Permissions.ToolExecute"/> permission.</summary>
    public const string ToolExecute = "ToolExecute";

    /// <summary>Requires <see cref="Permissions.AgentApprove"/>.</summary>
    public const string AgentApprove = "AgentApprove";
}
