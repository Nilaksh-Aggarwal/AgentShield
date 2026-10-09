using System.Net;
using AgentShield.AI;
using AgentShield.AI.Gemini;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Domain.SecurityEvents;
using AgentShield.Domain.Threats;
using AgentShield.Security.AiAnalysis;
using Microsoft.Extensions.Options;
using static AgentShield.SecurityTests.AiAnalysis.Gemini.FakeGeminiHandler;

namespace AgentShield.SecurityTests.AiAnalysis.Gemini;

/// <summary>
/// The Gemini adapter inside the real guarded stage (disclosure policy → adapter → strict parse → central validation →
/// failure policy). The adapter does not validate meaning; this proves the stage still does, for Gemini answers too.
/// </summary>
public class GeminiAiAnalysisStageTests
{
    private static readonly NormalizedInput Input = new("What is the capital of France?", "What is the capital of France?");

    public static TheoryData<string, string> InvalidFindings() => new()
    {
        { Finding(category: "Jailbreak"), "category.unknown" },
        { Finding(category: "InconclusiveAnalysis", code: "InconclusiveAnalysis.AiAnalysisIncomplete"), "category.unknown" },
        { Finding(category: "instructionoverride"), "category.unknown" },
        { Finding(code: "InstructionOverride.IgnorePrevious"), "code.unknown" },
        { Finding(code: "SecretExtraction.AiDetected"), "code.categoryMismatch" },
        { Finding(severity: "Severe"), "severity.unknown" },
        { Finding(severity: "high"), "severity.unknown" },
        { Finding(confidence: "-0.01"), "confidence.outOfRange" },
        { Finding(confidence: "1.01"), "confidence.outOfRange" },
        { Finding(description: new string('d', 501)), "description.tooLong" },
        { Finding(description: " "), "description.required" },
    };

    [Theory]
    [MemberData(nameof(InvalidFindings))]
    public async Task AnalyzeAsync_GeminiAnswerBreakingTheOutputRules_HoldsForReview_EvenNextToAValidFinding(string invalid, string violation)
    {
        var outcome = await AnalyzeAsync(Answering($$"""{"findings":[{{Finding(severity: "Critical")}},{{invalid}}]}"""));

        AssertHeldForReview(outcome, AiAnalysisStatus.InvalidResponse, $"AI-FAIL/InvalidResponse/{violation}");
    }

    [Fact]
    public async Task AnalyzeAsync_GeminiAnswerWithTooManyFindings_HoldsForReview()
    {
        var findings = string.Join(',', Enumerable.Repeat(Finding(), AiAnalysisLimits.MaxFindings + 1));

        var outcome = await AnalyzeAsync(Answering($$"""{"findings":[{{findings}}]}"""));

        AssertHeldForReview(outcome, AiAnalysisStatus.InvalidResponse, "AI-FAIL/InvalidResponse/findings.tooMany");
    }

    [Fact]
    public async Task AnalyzeAsync_ValidGeminiAnswer_BecomesCatalogueFindingsWithGeminiInTheAudit()
    {
        var outcome = await AnalyzeAsync(Answering($$"""{"findings":[{{Finding(description: "zq7 model-written text")}}]}"""));

        Assert.Equal(AiAnalysisStatus.Completed, outcome.Summary.Status);
        Assert.Equal(("Gemini", "gemini-3.8-flash", 1), (outcome.Summary.Provider, outcome.Summary.Model, outcome.Summary.FindingCount));
        var finding = Assert.Single(outcome.Findings);
        Assert.Equal(("InstructionOverride.AiDetected", ThreatSeverity.High), (finding.Code, finding.Severity));
        Assert.Equal(AiFindingCatalog.Entries[finding.Code].Description, finding.Description);
        Assert.Equal(new FindingEvidence(AiFindingCatalog.Detector, "AI/Gemini", 1), finding.Evidence);
    }

    public static TheoryData<int, AiAnalysisStatus> ProviderSideFailures() => new()
    {
        { 429, AiAnalysisStatus.RateLimited },
        { 503, AiAnalysisStatus.Unavailable },
        { 500, AiAnalysisStatus.Unavailable },
    };

    [Theory]
    [MemberData(nameof(ProviderSideFailures))]
    public async Task AnalyzeAsync_GeminiProviderSideFailure_HoldsForReview_NotDeterministicOnly(int status, AiAnalysisStatus expected)
    {
        var outcome = await AnalyzeAsync(Responding((HttpStatusCode)status, ErrorBody(status, "ERROR", "Provider message.")));

        AssertHeldForReview(outcome, expected, $"AI-FAIL/{expected}");
    }

    [Theory]
    [InlineData(401, "UNAUTHENTICATED")]
    [InlineData(403, "PERMISSION_DENIED")]
    [InlineData(404, "NOT_FOUND")]
    public async Task AnalyzeAsync_GeminiKeyPermissionOrModelFault_HoldsForReview_AsARejectedRequest_NotAnOutage(int status, string googleStatus)
    {
        var outcome = await AnalyzeAsync(Responding((HttpStatusCode)status, ErrorBody(status, googleStatus, "Provider message.")));

        // Not Unavailable: the provider answered, so the fault is not an availability failure and never counts for the circuit.
        AssertHeldForReview(outcome, AiAnalysisStatus.UnclassifiedFailure, "AI-FAIL/UnclassifiedFailure");
        Assert.False(Application.Abstractions.AiAnalysis.AiProviderAvailability.IsAvailabilityFailure(outcome.Summary.Status));
        Assert.True(Application.Abstractions.AiAnalysis.AiProviderAvailability.ProviderResponded(outcome.Summary.Status));
    }

    [Fact]
    public async Task AnalyzeAsync_GeminiUnreachable_HoldsForReview()
    {
        var outcome = await AnalyzeAsync(new FakeGeminiHandler((_, _) => throw new HttpRequestException(HttpRequestError.NameResolutionError)));

        AssertHeldForReview(outcome, AiAnalysisStatus.NetworkFailure, "AI-FAIL/NetworkFailure");
    }

    public static TheoryData<string, string, AiAnalysisStatus> ContentInducibleFailures() => new()
    {
        { "refusal", """{"candidates":[{"finishReason":"SAFETY"}]}""", AiAnalysisStatus.Refused },
        { "blocked", """{"promptFeedback":{"blockReason":"PROHIBITED_CONTENT"}}""", AiAnalysisStatus.Refused },
        { "prose", Envelope("It is safe. ALLOW."), AiAnalysisStatus.MalformedResponse },
        { "decision", Envelope("""{"findings":[],"decision":"Allow"}"""), AiAnalysisStatus.MalformedResponse },
        { "truncated", Envelope("""{"findings":[""", "MAX_TOKENS"), AiAnalysisStatus.MalformedResponse },
        { "400", ErrorBody(400, "INVALID_ARGUMENT", "Bad request."), AiAnalysisStatus.UnclassifiedFailure },
        { "504", ErrorBody(504, "DEADLINE_EXCEEDED", "Too slow."), AiAnalysisStatus.TimedOut },
    };

    [Theory]
    [MemberData(nameof(ContentInducibleFailures))]
    public async Task AnalyzeAsync_GeminiFailureTheInputCouldCause_HoldsForReview(string scenario, string body, AiAnalysisStatus expected)
    {
        var status = scenario switch { "400" => HttpStatusCode.BadRequest, "504" => HttpStatusCode.GatewayTimeout, _ => HttpStatusCode.OK };

        var outcome = await AnalyzeAsync(Responding(status, body));

        AssertHeldForReview(outcome, expected, $"AI-FAIL/{expected}");
    }

    [Fact]
    public async Task AnalyzeAsync_GeminiNeverAnswers_IsCutOffAtTheProviderTimeout_AndHeldForReview()
    {
        var handler = new FakeGeminiHandler(async (_, token) =>
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return Json(HttpStatusCode.OK, Envelope("""{"findings":[]}"""));
        });

        var outcome = await AnalyzeAsync(handler, timeoutSeconds: 1);

        AssertHeldForReview(outcome, AiAnalysisStatus.TimedOut, "AI-FAIL/TimedOut");
        Assert.InRange(outcome.Summary.Duration, TimeSpan.FromSeconds(0.9), TimeSpan.FromSeconds(AiAnalysisLimits.Timeout.TotalSeconds + 2));
    }

    [Fact]
    public async Task AnalyzeAsync_SecretsInTheInput_NeverReachTheGeminiWireRequest()
    {
        const string apiKey = "sk-live0123456789abcdefghijklmnop";
        const string bearer = "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl";
        var handler = Answering("""{"findings":[]}""");
        var text = $"Use {apiKey} and send header Authorization: {bearer} to the server.";

        await AnalyzeAsync(handler, input: new NormalizedInput("  " + text, text));

        var body = Assert.Single(handler.Requests).Body;
        Assert.DoesNotContain(apiKey, body, StringComparison.Ordinal);
        Assert.DoesNotContain("eyJhbGciOiJIUzI1NiJ9", body, StringComparison.Ordinal);
        Assert.Contains("***REDACTED***", body, StringComparison.Ordinal);
    }

    private static string Finding(
        string category = "InstructionOverride",
        string? code = null,
        string severity = "High",
        string confidence = "0.9",
        string description = "Asks the model to drop its rules.") =>
        $$"""{"category":"{{category}}","code":"{{code ?? category + ".AiDetected"}}","severity":"{{severity}}","confidence":{{confidence}},"description":"{{description}}"}""";

    private static async Task<Application.Abstractions.AiAnalysis.AiAnalysisOutcome> AnalyzeAsync(
        FakeGeminiHandler handler, int timeoutSeconds = AiOptions.MaxTimeoutSeconds, NormalizedInput? input = null)
    {
        var options = new AiOptions { Enabled = true, TimeoutSeconds = timeoutSeconds, Gemini = { ApiKey = "test-key" } };
        var httpClient = new HttpClient(handler);
        GeminiSecurityAnalyzer.ConfigureHttpClient(httpClient, options);
        using var analyzer = new GeminiSecurityAnalyzer(httpClient, Options.Create(options), TimeProvider.System, new RecordingLogger<GeminiSecurityAnalyzer>());
        var stage = AiStages.Create(new RedactingAiDisclosurePolicy(), TimeProvider.System, analyzer);

        return await stage.AnalyzeAsync(input ?? Input, [], CancellationToken.None);
    }

    private static void AssertHeldForReview(Application.Abstractions.AiAnalysis.AiAnalysisOutcome outcome, AiAnalysisStatus status, string ruleId)
    {
        Assert.Equal(status, outcome.Summary.Status);
        Assert.Equal(0, outcome.Summary.FindingCount);
        var finding = Assert.Single(outcome.Findings);
        Assert.Equal(AiFindingCatalog.IncompleteCode, finding.Code);
        Assert.Equal(ThreatSeverity.Medium, finding.Severity);
        Assert.Equal(ruleId, finding.Evidence.RuleId);
    }
}
