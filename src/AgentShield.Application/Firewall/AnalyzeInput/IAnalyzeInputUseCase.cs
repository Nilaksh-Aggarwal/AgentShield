using AgentShield.Application.Common.Results;

namespace AgentShield.Application.Firewall.AnalyzeInput;

/// <summary>
/// Analyses untrusted input and decides whether it may proceed:
/// normalisation → detection (every detector) → AI-assisted analysis (optional) → finding fusion → risk → policy →
/// security event.
/// </summary>
/// <remarks>
/// Expects a request that passed <see cref="AnalyzeInputRequestValidator"/>. Any decision, including
/// <c>Block</c>, is a successful result.
/// </remarks>
public interface IAnalyzeInputUseCase
{
    Task<Result<AnalysisResponse>> ExecuteAsync(AnalyzeInputRequest request, CancellationToken cancellationToken);
}
