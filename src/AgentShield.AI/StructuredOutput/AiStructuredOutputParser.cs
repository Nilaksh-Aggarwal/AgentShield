using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Common.Results;

namespace AgentShield.AI.StructuredOutput;

/// <summary>
/// Reads a model's structured output (the JSON text of its answer) into <see cref="AiAnalysisOutput"/>, strictly. Every
/// provider adapter uses this, so the wire contract is enforced once. Checks syntax only; the meaning of each value is
/// validated centrally in the Security layer.
/// </summary>
/// <remarks>
/// <para>Rejected as <see cref="AiAnalysisErrors.MalformedResponse"/>: empty text; more than
/// <see cref="MaxResponseBytes"/> UTF-8 bytes; anything but one JSON object; unknown members (including any attempt to
/// return a <c>decision</c>, <c>score</c> or <c>verdict</c>); duplicate or differently cased members; numbers written
/// as strings and strings written as numbers; comments, trailing commas; nesting deeper than <see cref="MaxDepth"/>.</para>
/// <para>The same strictness as the API's request bodies (ADR 0009), for the same reason: one text, one interpretation.
/// A model that was manipulated into producing something else gets no lenient reading.</para>
/// </remarks>
internal static class AiStructuredOutputParser
{
    /// <summary>
    /// Largest answer read. A complete answer at the output limits (16 findings × 500-character descriptions) is about
    /// 11 KB; 32 KiB leaves room for escaping and multi-byte text without letting a runaway model buffer megabytes.
    /// </summary>
    public const int MaxResponseBytes = 32 * 1024;

    /// <summary>The contract nests three levels (object → findings array → finding object).</summary>
    public const int MaxDepth = 8;

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = false,
        AllowDuplicateProperties = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        NumberHandling = JsonNumberHandling.Strict,
        ReadCommentHandling = JsonCommentHandling.Disallow,
        AllowTrailingCommas = false,
        MaxDepth = MaxDepth,
    };

    public static Result<AiAnalysisOutput> Parse(string? json)
    {
        // Length first: a string longer than the byte limit is over it in UTF-8 too, without counting.
        if (string.IsNullOrWhiteSpace(json) || json.Length > MaxResponseBytes || Encoding.UTF8.GetByteCount(json) > MaxResponseBytes)
        {
            return AiAnalysisErrors.MalformedResponse();
        }

        try
        {
            return JsonSerializer.Deserialize<AiAnalysisOutput>(json, Options) is { } output
                ? output
                : AiAnalysisErrors.MalformedResponse();
        }
        catch (JsonException)
        {
            return AiAnalysisErrors.MalformedResponse();
        }
        catch (ArgumentException)
        {
            // Text that cannot be transcoded to UTF-8 (lone surrogates).
            return AiAnalysisErrors.MalformedResponse();
        }
    }
}
