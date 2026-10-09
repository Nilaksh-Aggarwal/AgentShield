using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;

namespace AgentShield.Application.Abstractions.Agents;

/// <summary>
/// One tool action AgentShield can execute: the execution layer behind the tool gateway. Implemented by tool adapters
/// (today one in-memory reference tool in Infrastructure).
/// </summary>
/// <remarks>
/// <para>An executor runs its action and nothing else: it never decides whether a call is allowed, and it receives only
/// arguments its action's argument policy accepted (<see cref="ToolArguments"/>), never raw JSON.</para>
/// <para><b>Complete mediation:</b> the only component that may depend on this interface is the execution authority
/// (<see cref="IToolExecutionAuthority"/>), which calls an executor only for a verified, consumed execution grant. No
/// controller, use case or other service holds an executor, and no endpoint reaches one directly (pinned by tests).</para>
/// <para>Executors are singletons (stateless adapters), resolved once by the execution authority.</para>
/// </remarks>
public interface IToolExecutor
{
    ToolId Tool { get; }

    ActionName Action { get; }

    ValueTask<ToolOutput> ExecuteAsync(ToolArguments arguments, CancellationToken cancellationToken);
}
