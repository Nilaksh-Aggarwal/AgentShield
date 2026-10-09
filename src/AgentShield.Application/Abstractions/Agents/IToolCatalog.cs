using AgentShield.Domain.Agents;

namespace AgentShield.Application.Abstractions.Agents;

/// <summary>
/// The tool actions AgentShield knows: for each, the capability that authorises it and the effects that set its risk.
/// Trusted, read-only data; an action that is not here is unknown and blocked.
/// </summary>
/// <remarks>
/// Today a fixed reference catalogue in the Security layer (docs/decisions/0020-agent-action-authorization-boundary.md).
/// Real tool integrations (internal tools, MCP servers, external APIs) would register their actions behind this port, each
/// with declared effects.
/// </remarks>
public interface IToolCatalog
{
    /// <summary>Every catalogued action.</summary>
    IReadOnlyCollection<ToolActionDefinition> Actions { get; }

    /// <summary>Every capability some catalogued action requires; granting anything else is a configuration error.</summary>
    IReadOnlySet<Capability> Capabilities { get; }

    /// <summary>Whether <paramref name="tool"/> has at least one catalogued action.</summary>
    bool HasTool(ToolId tool);

    /// <summary>The definition of <paramref name="action"/> of <paramref name="tool"/>, or <see langword="null"/>.</summary>
    ToolActionDefinition? Find(ToolId tool, ActionName action);
}
