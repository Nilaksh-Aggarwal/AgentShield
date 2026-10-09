using System.Text.Json;
using AgentShield.ApiTests.Infrastructure;

namespace AgentShield.ApiTests.OpenApi;

/// <summary>The OpenAPI document describes the analyze endpoint as it actually behaves.</summary>
public class FirewallSwaggerTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task AnalyzeOperation_DocumentsExactlyTheStatusCodesItProduces()
    {
        var operation = await GetAnalyzeOperationAsync();

        var statuses = operation.GetProperty("responses").EnumerateObject().Select(response => response.Name);
        Assert.Equal(["200", "400", "401", "403", "422", "429", "500"], statuses.Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task AnalyzeOperation_DescribesSuccessAsEnvelopeAndErrorsAsProblemDetails()
    {
        var operation = await GetAnalyzeOperationAsync();
        var responses = operation.GetProperty("responses");

        Assert.EndsWith("AnalysisResponseApiResponse", SchemaRef(responses.GetProperty("200"), "application/json"), StringComparison.Ordinal);
        Assert.EndsWith("/ProblemDetails", SchemaRef(responses.GetProperty("400"), "application/problem+json"), StringComparison.Ordinal);
        Assert.EndsWith("/ValidationProblemDetails", SchemaRef(responses.GetProperty("422"), "application/problem+json"), StringComparison.Ordinal);
        Assert.EndsWith("/ProblemDetails", SchemaRef(responses.GetProperty("500"), "application/problem+json"), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnalyzeOperation_AcceptsOnlyJsonWithTheInputProperty()
    {
        var document = await GetDocumentAsync();
        var operation = Analyze(document);

        var content = operation.GetProperty("requestBody").GetProperty("content");
        Assert.Equal(["application/json"], content.EnumerateObject().Select(media => media.Name));

        var request = document.RootElement.GetProperty("components").GetProperty("schemas").GetProperty("AnalyzeInputRequest");
        Assert.Equal(["input"], request.GetProperty("properties").EnumerateObject().Select(property => property.Name));
    }

    [Theory]
    [InlineData("SecurityDecision", new[] { "Allow", "Review", "Block" })]
    [InlineData("RiskLevel", new[] { "Low", "Medium", "High", "Critical" })]
    [InlineData("ThreatSeverity", new[] { "Low", "Medium", "High", "Critical" })]
    [InlineData("ThreatCategory", new[] { "InstructionOverride", "RoleManipulation", "SecretExtraction", "Obfuscation", "InconclusiveAnalysis" })]
    public async Task ResponseEnums_AreDescribedAsTheirNames(string schemaName, string[] expected)
    {
        var document = await GetDocumentAsync();

        var schema = document.RootElement.GetProperty("components").GetProperty("schemas").GetProperty(schemaName);
        Assert.Equal("string", schema.GetProperty("type").GetString());
        Assert.Equal(expected, schema.GetProperty("enum").EnumerateArray().Select(value => value.GetString()));
    }

    private async Task<JsonDocument> GetDocumentAsync() =>
        JsonDocument.Parse(await _client.GetStringAsync("/swagger/v1/swagger.json"));

    private async Task<JsonElement> GetAnalyzeOperationAsync()
    {
        using var document = await GetDocumentAsync();
        return Analyze(document).Clone();
    }

    private static JsonElement Analyze(JsonDocument document) =>
        document.RootElement.GetProperty("paths").GetProperty("/api/v1/firewall/analyze").GetProperty("post");

    private static string SchemaRef(JsonElement response, string mediaType) =>
        response.GetProperty("content").GetProperty(mediaType).GetProperty("schema").GetProperty("$ref").GetString()!;
}
