using System.Text.Json;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using FluentValidation;

namespace AgentShield.Application.Agents.ExecuteTool;

/// <summary>
/// A request to execute a tool action through the tool gateway (body of <c>POST /api/v1/agent/tools/execute</c>). The tool
/// runs only if AgentShield allows it.
/// </summary>
/// <remarks>
/// <para>There is no agent field: the agent is the one whose gateway identity the authenticated API client is
/// (<see cref="AgentProfile.GatewayClient"/>). There is no field for a decision, a risk level, grants, an authorization
/// result, an execution authorization or a credential either: strict JSON turns any such property into a 400 (ADR 0009),
/// so nothing the caller sends can assert authority.</para>
/// <para>Names must be exact (lower-case ASCII, see <see cref="AgentIdentifiers"/>); nothing is normalised. The arguments
/// must be a JSON object; what it may contain is the action's argument policy's decision (a broken rule blocks the call).</para>
/// </remarks>
/// <param name="Tool">The tool (e.g. <c>knowledge</c>).</param>
/// <param name="Action">The operation of that tool (e.g. <c>lookup</c>).</param>
/// <param name="Capability">The capability the agent claims authorises the action (e.g. <c>knowledge:read</c>); it must be
/// exactly the one the action requires.</param>
/// <param name="Arguments">The tool call's arguments, a JSON object (for <c>knowledge.lookup</c>: <c>{ "query": "…" }</c>).</param>
/// <param name="InputDecision">Optional: the caller's report of the firewall's decision about the untrusted input behind this
/// call (<c>Allow</c>, <c>Review</c> or <c>Block</c>). It can only make the decision stricter; it never replaces the server's
/// record of an input event.</param>
/// <param name="InputEventId">Optional: the security event of the firewall analysis of the input behind this call (from the
/// analysis response). The gateway looks it up in its own record: it must be this client's analysis, in this trace (same
/// correlation ID), and recent; its decision then applies, whatever <paramref name="InputDecision"/> says. An event that
/// cannot be verified blocks the call.</param>
/// <param name="ApprovalId">Optional: a person's approval of exactly this call, after the gateway held it for review and
/// returned the approval's ID. It authorises one execution of the same call by the same agent, while it is approved and
/// unexpired; anything else is blocked.</param>
public sealed record ExecuteToolRequest(
    string? Tool,
    string? Action,
    string? Capability,
    JsonElement? Arguments,
    SecurityDecision? InputDecision,
    Guid? InputEventId = null,
    Guid? ApprovalId = null);

public sealed class ExecuteToolRequestValidator : AbstractValidator<ExecuteToolRequest>
{
    public const string InvalidNameCode = "AgentAction.InvalidName";
    public const string InvalidCapabilityCode = "AgentAction.InvalidCapability";
    public const string InvalidArgumentsCode = "ToolExecution.InvalidArguments";

    // The messages describe the format, never the rejected value (the same wording as the authorization endpoint).
    private const string NameFormat =
        "must be 1-64 characters of lower-case letters, digits, '.', '_' and '-', starting with a letter or digit.";

    private const string CapabilityFormat =
        "must be 'resource:operation': two parts of lower-case letters, digits, '_' and '-', at most 64 characters in all.";

    public ExecuteToolRequestValidator()
    {
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

        // Missing and null are the same "no value" (422); the members are the argument policy's to judge.
        RuleFor(request => request.Arguments).NotNull();
        RuleFor(request => request.Arguments)
            .Must(arguments => arguments!.Value.ValueKind == JsonValueKind.Object)
            .WithMessage("'Arguments' must be a JSON object.")
            .WithErrorCode(InvalidArgumentsCode)
            .When(request => request.Arguments is not null);
    }
}
