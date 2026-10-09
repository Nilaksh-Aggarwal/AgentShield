using AgentShield.Domain.Policy;

namespace AgentShield.Domain.Agents;

/// <summary>
/// How the tool gateway handled one execution request: whether the tool ran and, if not, which stage stopped it. Each
/// outcome has exactly one decision (<see cref="ToolExecutionOutcomes.DecisionFor"/>), so the two cannot disagree.
/// </summary>
/// <remarks>
/// The stages run in order: the referenced input security event → authorization boundary → (for a Review, a person's
/// approval) → executable tool → argument policy → execution grant → tool. Only the boundary's Allow, or its Review with a
/// matching approval, lets a request past the boundary, and every later stage can only turn that into a Block.
/// </remarks>
public enum ToolExecutionOutcome
{
    /// <summary>Allow: the action was authorised, its grant verified and consumed, and the tool ran.</summary>
    Executed = 1,

    /// <summary>Review: the authorization boundary held the action for a person's approval. The tool did not run. When the
    /// gateway could run the action, a pending approval was created for exactly this call.</summary>
    HeldForReview = 2,

    /// <summary>Block: the authorization boundary blocked the action. The tool did not run.</summary>
    Denied = 3,

    /// <summary>Block: the boundary allowed the action, but its arguments broke the action's argument policy. The tool did
    /// not run.</summary>
    ArgumentsRejected = 4,

    /// <summary>Block: the boundary allowed the action, but the gateway has no tool that executes it. Nothing ran.</summary>
    ToolUnavailable = 5,

    /// <summary>Block: the execution authority refused the execution grant (expired, used, altered or for another
    /// execution). The tool did not run.</summary>
    ExecutionAuthorizationRejected = 6,

    /// <summary>Allow: the action was authorised and the tool was invoked, but it failed. No result was returned.</summary>
    ExecutionFailed = 7,

    /// <summary>Block: the input security event the request referenced could not be verified (unknown, expired, or created by
    /// another client or in another trace), so its decision cannot be the server's. The tool did not run.</summary>
    InputContextRejected = 8,

    /// <summary>Block: the boundary held the action for review, and the approval the request presented is not an approved,
    /// unused, unexpired approval of exactly this call. The tool did not run.</summary>
    ApprovalRejected = 9,
}

/// <summary>The decision each <see cref="ToolExecutionOutcome"/> stands for, and whether the tool was invoked.</summary>
public static class ToolExecutionOutcomes
{
    /// <summary>The gateway's decision for <paramref name="outcome"/>. Only an invoked tool was allowed.</summary>
    public static SecurityDecision DecisionFor(ToolExecutionOutcome outcome) => outcome switch
    {
        ToolExecutionOutcome.Executed or ToolExecutionOutcome.ExecutionFailed => SecurityDecision.Allow,
        ToolExecutionOutcome.HeldForReview => SecurityDecision.Review,
        ToolExecutionOutcome.Denied
            or ToolExecutionOutcome.ArgumentsRejected
            or ToolExecutionOutcome.ToolUnavailable
            or ToolExecutionOutcome.ExecutionAuthorizationRejected
            or ToolExecutionOutcome.InputContextRejected
            or ToolExecutionOutcome.ApprovalRejected => SecurityDecision.Block,
        _ => throw new ArgumentOutOfRangeException(nameof(outcome), outcome, "Unknown tool execution outcome."),
    };

    /// <summary>Whether the tool was invoked: only after a verified, consumed grant.</summary>
    public static bool ToolWasInvoked(ToolExecutionOutcome outcome) =>
        DecisionFor(outcome) == SecurityDecision.Allow;
}
