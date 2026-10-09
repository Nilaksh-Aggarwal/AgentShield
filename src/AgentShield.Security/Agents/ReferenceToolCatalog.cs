using System.Collections.Frozen;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.Agents;

namespace AgentShield.Security.Agents;

/// <summary>
/// AgentShield's reference tool catalogue: a small, fixed set of representative tool actions, enough to exercise every
/// risk level and every policy rule. These are definitions only; the one action AgentShield can also execute, through the
/// tool gateway, is <c>knowledge.lookup</c> (a read-only lookup in a fixed in-memory dataset).
/// </summary>
/// <remarks>
/// <para>Defined in code because each entry is security policy (which capability authorises the action, which effects set
/// its risk) and is pinned by tests. Several actions of one tool carry different risks (<c>email</c>: read, draft, send),
/// and one capability can authorise several actions (<c>data:read</c>: describe, read).</para>
/// <list type="table">
/// <item><term>Low</term><description>data.describe, data.read, email.read, file.read, knowledge.lookup</description></item>
/// <item><term>Medium</term><description>data.write, email.draft, file.write</description></item>
/// <item><term>High</term><description>email.send, browser.navigate, browser.submit, customer.update</description></item>
/// <item><term>Critical</term><description>data.delete, payment.execute, secrets.read, identity.grant</description></item>
/// </list>
/// </remarks>
internal sealed class ReferenceToolCatalog : IToolCatalog, ISingletonService
{
    private static readonly ToolActionDefinition[] Definitions =
    [
        Define("data", "describe", "data:read", ActionEffects.MetadataLookup),
        Define("data", "read", "data:read", ActionEffects.ReadOnly),
        Define("data", "write", "data:write", ActionEffects.ModifiesData),
        Define("data", "delete", "data:delete", ActionEffects.Destructive),
        Define("email", "read", "email:read", ActionEffects.ReadOnly),
        Define("email", "draft", "email:draft", ActionEffects.DraftForApproval),
        Define("email", "send", "email:send", ActionEffects.ExternalCommunication),
        Define("file", "read", "file:read", ActionEffects.ReadOnly),
        Define("file", "write", "file:write", ActionEffects.ModifiesData),
        // A page load reaches a third-party host and can carry data in its URL, so navigating is external communication.
        Define("browser", "navigate", "browser:navigate", ActionEffects.ExternalCommunication),
        Define("browser", "submit", "browser:submit", ActionEffects.ExternalCommunication | ActionEffects.ModifiesData),
        Define("customer", "update", "customer:write", ActionEffects.ModifiesSensitiveData),
        Define("payment", "execute", "payment:execute", ActionEffects.Financial),
        Define("secrets", "read", "secrets:read", ActionEffects.CredentialAccess),
        Define("identity", "grant", "identity:grant", ActionEffects.PrivilegeChange),
        // The tool gateway's reference tool: reads from a fixed in-memory dataset, nothing else (Milestone 11).
        Define("knowledge", "lookup", "knowledge:read", ActionEffects.ReadOnly),
    ];

    private readonly FrozenDictionary<(ToolId Tool, ActionName Action), ToolActionDefinition> _byAction =
        Definitions.ToFrozenDictionary(definition => (definition.Tool, definition.Action));

    private readonly FrozenSet<ToolId> _tools = Definitions.Select(definition => definition.Tool).ToFrozenSet();

    // A read-only view: the array itself would let a caller cast it back and overwrite an entry.
    public IReadOnlyCollection<ToolActionDefinition> Actions { get; } = Array.AsReadOnly(Definitions);

    public IReadOnlySet<Capability> Capabilities { get; } = Definitions.Select(definition => definition.RequiredCapability).ToFrozenSet();

    public bool HasTool(ToolId tool)
    {
        ArgumentNullException.ThrowIfNull(tool);
        return _tools.Contains(tool);
    }

    public ToolActionDefinition? Find(ToolId tool, ActionName action)
    {
        ArgumentNullException.ThrowIfNull(tool);
        ArgumentNullException.ThrowIfNull(action);
        return _byAction.GetValueOrDefault((tool, action));
    }

    private static ToolActionDefinition Define(string tool, string action, string capability, ActionEffects effects) =>
        new(new ToolId(tool), new ActionName(action), new Capability(capability), effects);
}
