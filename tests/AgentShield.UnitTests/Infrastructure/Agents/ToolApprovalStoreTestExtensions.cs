using AgentShield.Application.Abstractions.Agents;

namespace AgentShield.UnitTests.Infrastructure.Agents;

/// <summary>Test setup: a person's decision as the use case makes it once recording succeeded (begun, then completed).</summary>
internal static class ToolApprovalStoreTestExtensions
{
    public static ToolApprovalDecision Decide(this IToolApprovalStore store, Guid approvalId, bool approve, string decidedBy, DateTimeOffset now)
    {
        var decision = store.TryBeginDecision(approvalId, approve, decidedBy, now);
        if (decision.Approval is not null)
        {
            store.CompleteDecision(approvalId);
        }

        return decision;
    }
}
