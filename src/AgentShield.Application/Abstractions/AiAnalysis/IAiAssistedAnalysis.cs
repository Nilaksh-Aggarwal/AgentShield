using AgentShield.Application.Abstractions.Security;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Domain.Threats;

namespace AgentShield.Application.Abstractions.AiAnalysis;

/// <summary>
/// The AI-assisted analysis stage of the firewall pipeline: calls the configured <see cref="IAiSecurityAnalyzer"/>
/// (if any) under a hard timeout, validates its untrusted output and turns it into findings. Implemented in the
/// Security layer. Decides nothing: its findings go through the same fusion, risk and policy as every detector's.
/// </summary>
/// <remarks>
/// <para>Contract for implementations:</para>
/// <list type="bullet">
/// <item>Never let AI output lower, remove or rewrite a deterministic finding: the stage only adds findings.</item>
/// <item>Accept a provider response all or nothing: if any part breaks the output contract, no AI finding is used.</item>
/// <item>Bound the call with a timeout and the caller's <see cref="CancellationToken"/>. Caller cancellation propagates
/// as <see cref="OperationCanceledException"/>; a timeout is an outcome, not an exception.</item>
/// <item>Express "hold for review" only as a finding, so the policy engine stays the only place a decision is made.</item>
/// <item>Put no model-written text, provider response or analysed content into a finding or the summary.</item>
/// </list>
/// </remarks>
public interface IAiAssistedAnalysis
{
    /// <param name="input">The normalised input the detectors analysed.</param>
    /// <param name="deterministicFindings">The fused findings of the deterministic detectors.</param>
    /// <param name="cancellationToken">The request's cancellation token.</param>
    Task<AiAnalysisOutcome> AnalyzeAsync(
        NormalizedInput input,
        IReadOnlyList<ThreatFinding> deterministicFindings,
        CancellationToken cancellationToken);
}

/// <summary>What the AI stage adds to one analysis.</summary>
/// <param name="Summary">Audit record of the stage (status, provider, model, duration, finding count).</param>
/// <param name="Findings">Findings to fuse with the deterministic ones: the validated AI findings, or the single finding
/// that holds the input for review after a failure the input may have caused. Empty when disabled, when the model found
/// nothing, or after a provider-side failure.</param>
public sealed record AiAnalysisOutcome(AiAnalysisSummary Summary, IReadOnlyList<ThreatFinding> Findings)
{
    /// <summary>No AI provider is configured.</summary>
    public static AiAnalysisOutcome Disabled { get; } = new(AiAnalysisSummary.Disabled, []);
}
