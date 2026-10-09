using AgentShield.Application.Common.Results;
using AgentShield.Domain.Threats;

namespace AgentShield.Application.Abstractions.AiAnalysis;

/// <summary>
/// Port to one AI provider (Azure OpenAI, OpenAI, a local model, a test double, ...) that performs AI-assisted
/// security analysis. Implemented in <c>AgentShield.AI</c>; the Application and Security layers never see provider SDKs,
/// HTTP clients, prompts or model-specific types.
/// </summary>
/// <remarks>
/// <para>The provider is an <b>untrusted external dependency</b>. It returns raw structured output
/// (<see cref="AiAnalysisOutput"/>), not <see cref="ThreatFinding"/>s: validation, mapping to findings, the timeout
/// and failure handling happen centrally in <see cref="IAiAssistedAnalysis"/>, so no provider adapter can skip them.
/// It never returns a security decision; the output contract has no field for one.</para>
/// <para>Contract for implementations:</para>
/// <list type="bullet">
/// <item>Send only <see cref="AiAnalysisRequest"/> (plus the adapter's own fixed instructions). Never add headers,
/// identifiers, logs or configuration values of AgentShield to what the model sees.</item>
/// <item>Honour <paramref name="cancellationToken"/> on every I/O call. The caller also enforces a hard timeout and
/// abandons a call that ignores cancellation.</item>
/// <item>Report expected failures as a failed <see cref="Result"/> with an <see cref="AiAnalysisErrors"/> error (timeout,
/// unavailable, rate limit, network failure, malformed response, refusal). Exceptions mean a bug: the analysis fails
/// closed (500).</item>
/// <item>Never retry automatically: a completion call costs money and time, and the request has a latency budget.</item>
/// <item>Never log the request content, the prompt or the raw response.</item>
/// </list>
/// <para>AI analysis is enabled by registering exactly one implementation (in <c>AddAI</c>). With none registered the
/// stage reports <see cref="Domain.SecurityEvents.AiAnalysisStatus.Disabled"/> and the deterministic pipeline decides
/// alone, exactly as before AI analysis existed.</para>
/// </remarks>
public interface IAiSecurityAnalyzer
{
    /// <summary>Stable provider identity for audit (e.g. <c>AzureOpenAI</c>). Configuration, never a secret.</summary>
    string Provider { get; }

    /// <summary>Model or deployment name for audit (e.g. <c>gpt-4o-mini-2024-07-18</c>). Configuration, never a secret.</summary>
    string Model { get; }

    Task<Result<AiAnalysisOutput>> AnalyzeAsync(AiAnalysisRequest request, CancellationToken cancellationToken);

    /// <summary>
    /// A conservative <b>upper bound</b> on the input tokens the provider will count for <paramref name="request"/>,
    /// including the adapter's own fixed instructions and anything else it sends. Used to reserve AgentShield's
    /// input-token budget before the call.
    /// </summary>
    /// <remarks>
    /// Local, deterministic and cheap: no I/O and <b>never</b> a provider token-counting request (that would cost quota,
    /// latency and a second failure mode per analysis). When unsure, over-estimate: an over-estimate costs budget, an
    /// under-estimate can exhaust the provider's quota. The stage never charges less than its own provider-agnostic
    /// floor, whatever this returns.
    /// </remarks>
    long EstimateInputTokens(AiAnalysisRequest request);
}

/// <summary>
/// Everything an AI provider is allowed to receive about one input. Deliberately minimal: see
/// docs/security/ai-analysis.md, "Input contract".
/// </summary>
/// <remarks>
/// Not included, by design: the original (un-normalised) input, correlation or security-event identifiers, HTTP
/// headers, caller identity, detector identities, rule IDs, match counts, transformation chains, finding descriptions,
/// risk scores, policy thresholds, configuration, logs and anything decoded by the obfuscation detector. Never log an
/// instance of this type: <see cref="Content"/> is user data.
/// </remarks>
/// <param name="Content">The normalised input after the disclosure policy (secret redaction, size limit). Never truncated.</param>
/// <param name="DeterministicFindings">What the deterministic detectors already found (fused, most severe first), as
/// category, code and severity only. Context for the model, not instructions.</param>
public sealed record AiAnalysisRequest(string Content, IReadOnlyList<AiContextFinding> DeterministicFindings);

/// <summary>A deterministic finding as disclosed to the AI provider: no evidence, rule IDs, confidence or description.</summary>
public sealed record AiContextFinding(ThreatCategory Category, string Code, ThreatSeverity Severity);
