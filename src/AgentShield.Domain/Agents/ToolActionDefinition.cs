namespace AgentShield.Domain.Agents;

/// <summary>
/// One action of a tool as AgentShield knows it: the capability an agent must hold to perform it and the effects it can
/// have. Trusted data, defined by AgentShield's tool catalogue, never by a request.
/// </summary>
public sealed record ToolActionDefinition
{
    /// <summary>Every effect a definition may declare.</summary>
    public const ActionEffects AllEffects =
        ActionEffects.ReadOnly | ActionEffects.MetadataLookup | ActionEffects.ModifiesData | ActionEffects.DraftForApproval
        | ActionEffects.ExternalCommunication | ActionEffects.ModifiesSensitiveData | ActionEffects.PrivilegedOperation
        | ActionEffects.Financial | ActionEffects.CredentialAccess | ActionEffects.Destructive | ActionEffects.PrivilegeChange;

    public ToolActionDefinition(ToolId tool, ActionName action, Capability requiredCapability, ActionEffects effects)
    {
        ArgumentNullException.ThrowIfNull(tool);
        ArgumentNullException.ThrowIfNull(action);
        ArgumentNullException.ThrowIfNull(requiredCapability);

        if (effects == ActionEffects.None)
        {
            throw new ArgumentException("A tool action must declare at least one effect.", nameof(effects));
        }

        if ((effects & ~AllEffects) != 0)
        {
            throw new ArgumentOutOfRangeException(nameof(effects), effects, "Unknown action effect.");
        }

        Tool = tool;
        Action = action;
        RequiredCapability = requiredCapability;
        Effects = effects;
    }

    public ToolId Tool { get; }

    public ActionName Action { get; }

    /// <summary>The one capability that authorises this action. Holding another capability of the same tool does not.</summary>
    public Capability RequiredCapability { get; }

    public ActionEffects Effects { get; }
}
