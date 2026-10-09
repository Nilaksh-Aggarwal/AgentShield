using System.Collections.Concurrent;
using AgentShield.AI.StructuredOutput;
using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Common.Results;

namespace AgentShield.IntegrationTests.AiAnalysis;

/// <summary>
/// A deterministic AI provider double registered in place of a real one. Answers with the JSON a model would return,
/// read through the real strict parser, and records every request it received.
/// </summary>
internal sealed class ScriptedAiSecurityAnalyzer(
    Func<AiAnalysisRequest, CancellationToken, Task<Result<AiAnalysisOutput>>> respond) : IAiSecurityAnalyzer
{
    public const string ProviderName = "Scripted";
    public const string ModelName = "scripted-model-1";

    public string Provider => ProviderName;

    public string Model => ModelName;

    public ConcurrentQueue<AiAnalysisRequest> Requests { get; } = new();

    public static ScriptedAiSecurityAnalyzer AnsweringJson(string json) =>
        new((_, _) => Task.FromResult(AiStructuredOutputParser.Parse(json)));

    public static ScriptedAiSecurityAnalyzer Failing(Error error) =>
        new((_, _) => Task.FromResult(Result.Failure<AiAnalysisOutput>(error)));

    public static string Finding(string category, string severity, double confidence = 0.9, string description = "Looks like an attack.") =>
        $$"""{"category":"{{category}}","code":"{{category}}.AiDetected","severity":"{{severity}}","confidence":{{confidence.ToString(System.Globalization.CultureInfo.InvariantCulture)}},"description":"{{description}}"}""";

    public static string Findings(params string[] findings) => $$"""{"findings":[{{string.Join(',', findings)}}]}""";

    /// <summary>What <see cref="EstimateInputTokens"/> answers; by default a small fixed overhead plus the content length.</summary>
    public Func<AiAnalysisRequest, long> Estimate { get; init; } = request => 100 + request.Content.Length;

    public long EstimateInputTokens(AiAnalysisRequest request) => Estimate(request);

    public Task<Result<AiAnalysisOutput>> AnalyzeAsync(AiAnalysisRequest request, CancellationToken cancellationToken)
    {
        Requests.Enqueue(request);
        return respond(request, cancellationToken);
    }
}
