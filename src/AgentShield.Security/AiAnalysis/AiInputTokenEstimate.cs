using System.Text;
using AgentShield.Application.Abstractions.AiAnalysis;

namespace AgentShield.Security.AiAnalysis;

/// <summary>
/// The input-token amount the stage reserves for one provider call: the provider adapter's own conservative estimate,
/// never below a provider-agnostic floor. Local and deterministic; never a provider request.
/// </summary>
/// <remarks>
/// <para><b>Floor: one token per UTF-8 byte</b> of everything taken from <see cref="AiAnalysisRequest"/> (the disclosed
/// content and the category, code and severity of every deterministic finding). Tokenisers used by hosted models
/// (byte-level BPE, SentencePiece with byte fallback) produce at most one token per UTF-8 byte of text, so the floor is
/// an upper bound for that text, whatever the language or script: about 4× the typical English count, 3× for CJK (3 bytes
/// per character, usually about one token), and exact for byte-fallback content such as rare symbols. Deliberately not
/// <c>characters / 4</c>, which under-counts CJK, emoji and Base64-like text badly.</para>
/// <para>The adapter adds what only it knows (its fixed instructions, schema and framing). Taking the maximum means an
/// adapter bug that under-reports (0, negative) can never shrink the reservation below the content itself.</para>
/// </remarks>
internal static class AiInputTokenEstimate
{
    /// <summary>The reservation for <paramref name="request"/> sent through <paramref name="analyzer"/>.</summary>
    public static long For(AiAnalysisRequest request, IAiSecurityAnalyzer analyzer)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(analyzer);

        return Math.Max(analyzer.EstimateInputTokens(request), Floor(request));
    }

    /// <summary>One token per UTF-8 byte of the request's own text (content and deterministic context).</summary>
    public static long Floor(AiAnalysisRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        long bytes = Encoding.UTF8.GetByteCount(request.Content);
        foreach (var finding in request.DeterministicFindings)
        {
            bytes += Encoding.UTF8.GetByteCount(finding.Code)
                + Encoding.UTF8.GetByteCount(finding.Category.ToString())
                + Encoding.UTF8.GetByteCount(finding.Severity.ToString());
        }

        return bytes;
    }
}
