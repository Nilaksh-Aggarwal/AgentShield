using System.Text.Json;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;

namespace AgentShield.Application.Abstractions.Agents;

/// <summary>
/// The argument policy of one executable tool action: turns the untrusted JSON arguments of a tool call into the action's
/// validated <see cref="ToolArguments"/>, or rejects them. Deterministic and bounded; implemented in the Security layer.
/// </summary>
/// <remarks>
/// <para>A small explicit schema per action (required members, types, lengths, no unexpected members), not a generic policy
/// language. The tool gateway applies it before any execution grant is issued; the tool itself never sees raw JSON, so it
/// cannot receive arguments the policy did not accept.</para>
/// <para>It decides nothing about who may call the action (that is the authorization boundary's job) and never throws for
/// bad input: every rejection is a <see cref="ToolArgumentViolation"/>, which never carries the value.</para>
/// </remarks>
public interface IToolArgumentPolicy
{
    ToolId Tool { get; }

    ActionName Action { get; }

    ToolArgumentCheck Check(JsonElement arguments);
}

/// <summary>The result of an argument policy: the validated arguments, or the rule they broke.</summary>
public sealed record ToolArgumentCheck
{
    private ToolArgumentCheck(ToolArguments? arguments, ToolArgumentViolation? violation)
    {
        Arguments = arguments;
        Violation = violation;
    }

    /// <summary>The validated arguments; <see langword="null"/> when they were rejected.</summary>
    public ToolArguments? Arguments { get; }

    /// <summary>The broken rule; <see langword="null"/> when the arguments were accepted.</summary>
    public ToolArgumentViolation? Violation { get; }

    public bool IsAccepted => Arguments is not null;

    public static ToolArgumentCheck Accept(ToolArguments arguments) =>
        new(arguments ?? throw new ArgumentNullException(nameof(arguments)), violation: null);

    public static ToolArgumentCheck Reject(ToolArgumentViolation violation) =>
        Enum.IsDefined(violation)
            ? new(arguments: null, violation)
            : throw new ArgumentOutOfRangeException(nameof(violation), violation, "Unknown argument violation.");
}
