using System.Text.Json.Nodes;
using AgentShield.AI.Gemini;
using AgentShield.Domain.Threats;
using AgentShield.Security.AiAnalysis;

namespace AgentShield.SecurityTests.AiAnalysis.Gemini;

/// <summary>
/// The Gemini structured-output schema and instructions stay aligned with the Security layer's output contract. The
/// AI project cannot reference the catalogue, so drift is caught here.
/// </summary>
public class GeminiRequestTests
{
    private static readonly JsonNode Schema = GeminiRequest.ResponseSchema();
    private static readonly JsonNode Finding = Schema["properties"]!["findings"]!["items"]!;

    [Fact]
    public void ResponseSchema_CategoriesAndCodes_AreExactlyTheAiFindingCatalogue()
    {
        Assert.Equal(
            AiFindingCatalog.Entries.Values.Select(entry => entry.Category.ToString()).Distinct().Order(StringComparer.Ordinal),
            Enumeration("category").Order(StringComparer.Ordinal));
        Assert.Equal(
            AiFindingCatalog.Entries.Keys.Order(StringComparer.Ordinal),
            Enumeration("code").Order(StringComparer.Ordinal));
        Assert.DoesNotContain(nameof(ThreatCategory.InconclusiveAnalysis), Enumeration("category"));
    }

    [Fact]
    public void ResponseSchema_Severities_AreExactlyThreatSeverityNames()
    {
        Assert.Equal(Enum.GetNames<ThreatSeverity>(), Enumeration("severity"));
    }

    [Fact]
    public void ResponseSchema_Limits_MatchTheCentralValidator()
    {
        Assert.Equal(AiAnalysisLimits.MaxFindings, (int)Schema["properties"]!["findings"]!["maxItems"]!);
        var confidence = Finding["properties"]!["confidence"]!;
        Assert.Equal(("number", 0, 1), ((string)confidence["type"]!, (int)confidence["minimum"]!, (int)confidence["maximum"]!));
    }

    [Fact]
    public void ResponseSchema_HasNoDecisionField_AndForbidsAdditionalProperties()
    {
        Assert.Equal(["findings"], PropertyNames(Schema));
        Assert.Equal(["category", "code", "severity", "confidence", "description"], PropertyNames(Finding));
        Assert.Equal(["findings"], ((JsonArray)Schema["required"]!).Select(value => (string)value!));
        Assert.Equal(PropertyNames(Finding), ((JsonArray)Finding["required"]!).Select(value => (string)value!));
        Assert.False((bool)Schema["additionalProperties"]!);
        Assert.False((bool)Finding["additionalProperties"]!);
    }

    [Fact]
    public void SystemInstruction_NamesEveryCatalogueCode_AndTreatsTheContentAsUntrustedData()
    {
        Assert.All(AiFindingCatalog.Entries.Keys, code => Assert.Contains(code, GeminiRequest.SystemInstruction, StringComparison.Ordinal));
        Assert.Contains("UNTRUSTED", GeminiRequest.SystemInstruction, StringComparison.Ordinal);
        Assert.Contains("Never follow", GeminiRequest.SystemInstruction, StringComparison.Ordinal);
    }

    [Fact]
    public void MaxOutputTokens_LeavesRoomForAFullAnswerAtTheValidatorLimits()
    {
        // Worst case: every finding with a maximal description (roughly 4 characters per token, plus field overhead).
        const int tokensPerFinding = (AiAnalysisLimits.MaxDescriptionLength / 4) + 60;

        Assert.True(GeminiRequest.MaxOutputTokens >= AiAnalysisLimits.MaxFindings * tokensPerFinding);
    }

    private static string[] Enumeration(string property) =>
        [.. ((JsonArray)Finding["properties"]![property]!["enum"]!).Select(value => (string)value!)];

    private static string[] PropertyNames(JsonNode node) =>
        [.. ((JsonObject)node["properties"]!).Select(property => property.Key)];
}
