using AgentShield.AI.StructuredOutput;
using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Common.Results;

namespace AgentShield.SecurityTests.AiAnalysis;

/// <summary>A deterministic AI provider double: answers from a script and records every request it received.</summary>
internal sealed class ScriptedAiSecurityAnalyzer(
    Func<AiAnalysisRequest, CancellationToken, Task<Result<AiAnalysisOutput>>> respond) : IAiSecurityAnalyzer
{
    public const string ProviderName = "Scripted";
    public const string ModelName = "scripted-model-1";

    public string Provider => ProviderName;

    public string Model => ModelName;

    public List<AiAnalysisRequest> Requests { get; } = [];

    public static ScriptedAiSecurityAnalyzer Returning(params AiFindingCandidate?[] findings) =>
        new((_, _) => Task.FromResult(Result.Success(new AiAnalysisOutput(findings))));

    public static ScriptedAiSecurityAnalyzer Failing(Error error) =>
        new((_, _) => Task.FromResult(Result.Failure<AiAnalysisOutput>(error)));

    /// <summary>A provider whose model answered with <paramref name="json"/>, read by the real strict parser.</summary>
    public static ScriptedAiSecurityAnalyzer ReturningJson(string json) =>
        new((_, _) => Task.FromResult(AiStructuredOutputParser.Parse(json)));

    public static AiFindingCandidate Candidate(
        string? category = "InstructionOverride",
        string? code = "InstructionOverride.AiDetected",
        string? severity = "High",
        double? confidence = 0.9,
        string? description = "The text asks the model to disregard its instructions.") =>
        new(category, code, severity, confidence, description);

    /// <summary>What <see cref="EstimateInputTokens"/> answers; by default a small fixed overhead plus the content length.</summary>
    public Func<AiAnalysisRequest, long> Estimate { get; init; } = request => 100 + request.Content.Length;

    public long EstimateInputTokens(AiAnalysisRequest request) => Estimate(request);

    public Task<Result<AiAnalysisOutput>> AnalyzeAsync(AiAnalysisRequest request, CancellationToken cancellationToken)
    {
        Requests.Add(request);
        return respond(request, cancellationToken);
    }
}
