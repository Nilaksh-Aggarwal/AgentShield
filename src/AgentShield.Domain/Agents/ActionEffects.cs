namespace AgentShield.Domain.Agents;

/// <summary>
/// What a tool action does to the world, declared by whoever defines the action. The risk of an action is classified from
/// these effects, never from the tool's or action's name (docs/security/agent-action-authorization.md).
/// </summary>
/// <remarks>
/// <para>An action declares every effect it can have; its risk is that of its most dangerous effect. The bands:</para>
/// <list type="table">
/// <item><term>Low</term><description><see cref="ReadOnly"/>, <see cref="MetadataLookup"/></description></item>
/// <item><term>Medium</term><description><see cref="ModifiesData"/>, <see cref="DraftForApproval"/></description></item>
/// <item><term>High</term><description><see cref="ExternalCommunication"/>, <see cref="ModifiesSensitiveData"/>,
/// <see cref="PrivilegedOperation"/></description></item>
/// <item><term>Critical</term><description><see cref="Financial"/>, <see cref="CredentialAccess"/>,
/// <see cref="Destructive"/>, <see cref="PrivilegeChange"/></description></item>
/// </list>
/// <para>An action with no declared effect is invalid (<see cref="ToolActionDefinition"/> rejects it): "no effect" is not a
/// safe default, it is an unclassified action.</para>
/// </remarks>
[Flags]
public enum ActionEffects
{
    /// <summary>Not a valid declaration on its own (see remarks).</summary>
    None = 0,

    /// <summary>Reads data without changing anything.</summary>
    ReadOnly = 1 << 0,

    /// <summary>Looks up metadata (names, sizes, schemas), not content.</summary>
    MetadataLookup = 1 << 1,

    /// <summary>Creates or changes data that is not sensitive.</summary>
    ModifiesData = 1 << 2,

    /// <summary>Prepares something (a message, a change) that a person approves before it takes effect.</summary>
    DraftForApproval = 1 << 3,

    /// <summary>Sends something outside the organisation or to a third party (an email, a web request, a form).</summary>
    ExternalCommunication = 1 << 4,

    /// <summary>Creates or changes sensitive data (customer, personal or regulated records).</summary>
    ModifiesSensitiveData = 1 << 5,

    /// <summary>Runs an operation that needs elevated rights but does not change who holds them.</summary>
    PrivilegedOperation = 1 << 6,

    /// <summary>Moves money or creates a financial obligation.</summary>
    Financial = 1 << 7,

    /// <summary>Reads or uses credentials, keys or other secrets.</summary>
    CredentialAccess = 1 << 8,

    /// <summary>Deletes or irreversibly overwrites data or resources.</summary>
    Destructive = 1 << 9,

    /// <summary>Changes who holds which rights (roles, grants, capabilities).</summary>
    PrivilegeChange = 1 << 10,
}
