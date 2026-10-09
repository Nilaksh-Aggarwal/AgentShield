using AgentShield.Application.Common.Results;

namespace AgentShield.Application.Agents.ExecuteTool;

/// <summary>
/// The tool gateway: executes a tool action for the authenticated agent if, and only if, AgentShield allows it. The
/// enforcement point that M10's decide-only boundary lacked (docs/security/tool-gateway.md).
/// </summary>
/// <remarks>
/// <para>Order: agent identity from the authenticated caller → authorization boundary (capability, risk, policy; M10,
/// unchanged) → an executable tool → the action's argument policy → a signed, single-use execution grant → the execution
/// authority verifies and consumes it and runs the tool once. Every stage is recorded before the next starts.</para>
/// <para>Expects a request that passed <see cref="ExecuteToolRequestValidator"/>. Every decision, including Block, is a
/// successful result; only Allow runs the tool.</para>
/// </remarks>
public interface IToolGateway
{
    Task<Result<ToolExecutionResponse>> ExecuteAsync(ExecuteToolRequest request, CancellationToken cancellationToken);
}
