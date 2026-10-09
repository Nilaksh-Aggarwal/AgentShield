using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using FluentValidation;

namespace AgentShield.Application.Agents.AuthorizeAgentAction;

/// <summary>
/// An agent's proposed tool action, submitted for an authorization decision (body of
/// <c>POST /api/v1/agent/actions/authorize</c>). Nothing is executed.
/// </summary>
/// <remarks>
/// Every field is untrusted. Names must be exact (lower-case ASCII, see <see cref="AgentIdentifiers"/>); nothing is
/// normalised, so a differently cased or look-alike name is rejected (422), never matched. The body has no field for tool
/// arguments, a decision, a risk level, extra capabilities or the agent's reasoning: strict JSON turns any such property
/// into a 400 (ADR 0009).
/// </remarks>
/// <param name="AgentId">The agent proposing the action (e.g. <c>support-agent</c>).</param>
/// <param name="Tool">The tool it wants to call (e.g. <c>email</c>).</param>
/// <param name="Action">The operation of that tool (e.g. <c>send</c>).</param>
/// <param name="Capability">The capability the agent claims authorises the action (e.g. <c>email:send</c>).</param>
/// <param name="InputDecision">Optional: the firewall's decision about the untrusted input behind this action
/// (<c>Allow</c>, <c>Review</c> or <c>Block</c>). It can only make the decision stricter.</param>
public sealed record AuthorizeAgentActionRequest(
    string? AgentId,
    string? Tool,
    string? Action,
    string? Capability,
    SecurityDecision? InputDecision);

public sealed class AuthorizeAgentActionRequestValidator : AbstractValidator<AuthorizeAgentActionRequest>
{
    public const string InvalidNameCode = "AgentAction.InvalidName";
    public const string InvalidCapabilityCode = "AgentAction.InvalidCapability";

    // The messages describe the format, never the rejected value.
    private const string NameFormat =
        "must be 1-64 characters of lower-case letters, digits, '.', '_' and '-', starting with a letter or digit.";

    private const string CapabilityFormat =
        "must be 'resource:operation': two parts of lower-case letters, digits, '_' and '-', at most 64 characters in all.";

    public AuthorizeAgentActionRequestValidator()
    {
        RuleFor(request => request.AgentId).NotEmpty();
        RuleFor(request => request.AgentId)
            .Must(AgentIdentifiers.IsValidName)
            .WithMessage("'Agent Id' " + NameFormat)
            .WithErrorCode(InvalidNameCode)
            .When(request => !string.IsNullOrEmpty(request.AgentId));

        RuleFor(request => request.Tool).NotEmpty();
        RuleFor(request => request.Tool)
            .Must(AgentIdentifiers.IsValidName)
            .WithMessage("'Tool' " + NameFormat)
            .WithErrorCode(InvalidNameCode)
            .When(request => !string.IsNullOrEmpty(request.Tool));

        RuleFor(request => request.Action).NotEmpty();
        RuleFor(request => request.Action)
            .Must(AgentIdentifiers.IsValidName)
            .WithMessage("'Action' " + NameFormat)
            .WithErrorCode(InvalidNameCode)
            .When(request => !string.IsNullOrEmpty(request.Action));

        RuleFor(request => request.Capability).NotEmpty();
        RuleFor(request => request.Capability)
            .Must(AgentIdentifiers.IsValidCapability)
            .WithMessage("'Capability' " + CapabilityFormat)
            .WithErrorCode(InvalidCapabilityCode)
            .When(request => !string.IsNullOrEmpty(request.Capability));
    }
}
