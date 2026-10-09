namespace AgentShield.Application.Abstractions.Context;

/// <summary>
/// The API clients configured for this deployment. Lets a component that shares a resource between clients (the AI
/// capacity gate) know every client up front, including clients that have not called yet, so that a share reserved for
/// one client cannot be taken by another before it arrives.
/// </summary>
public interface IApiClientDirectory
{
    /// <summary>IDs of the configured clients that are allowed to request firewall analyses. Never credentials.</summary>
    IReadOnlySet<string> AnalysisClientIds { get; }

    /// <summary>
    /// IDs of the configured clients that are allowed to request agent action authorizations: the only clients an agent can
    /// be bound to. Never credentials.
    /// </summary>
    IReadOnlySet<string> AgentAuthorizationClientIds { get; }

    /// <summary>
    /// IDs of the configured clients that are allowed to execute tools through the tool gateway. Each must be the gateway
    /// identity of exactly one agent (validated at startup). Never credentials.
    /// </summary>
    IReadOnlySet<string> ToolExecutionClientIds { get; }
}
