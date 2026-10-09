using System.Text.Json;
using AgentShield.ApiTests.Infrastructure;

namespace AgentShield.ApiTests.OpenApi;

/// <summary>The OpenAPI document describes the tool gateway endpoint as it actually behaves.</summary>
public class ToolGatewaySwaggerTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task ExecuteOperation_DocumentsExactlyTheStatusCodesItProduces()
    {
        using var document = await GetDocumentAsync();

        var statuses = Execute(document).GetProperty("responses").EnumerateObject().Select(response => response.Name);
        Assert.Equal(["200", "400", "401", "403", "422", "429", "500"], statuses.Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task ExecuteOperation_AcceptsOnlyTheDocumentedFields_AsJson_WithNoAgentOrAuthorityField()
    {
        using var document = await GetDocumentAsync();
        var schemas = document.RootElement.GetProperty("components").GetProperty("schemas");

        var content = Execute(document).GetProperty("requestBody").GetProperty("content");
        Assert.Equal(["application/json"], content.EnumerateObject().Select(media => media.Name));
        Assert.Equal(["action", "approvalId", "arguments", "capability", "inputDecision", "inputEventId", "tool"], PropertyNames(schemas.GetProperty("ExecuteToolRequest")));
    }

    [Fact]
    public async Task ExecuteOperation_DescribesSuccessAsAnEnvelopedOutcome_AndErrorsAsProblemDetails()
    {
        using var document = await GetDocumentAsync();
        var schemas = document.RootElement.GetProperty("components").GetProperty("schemas");
        var responses = Execute(document).GetProperty("responses");

        Assert.EndsWith("ToolExecutionResponseApiResponse", SchemaRef(responses.GetProperty("200"), "application/json"), StringComparison.Ordinal);
        Assert.EndsWith("/ValidationProblemDetails", SchemaRef(responses.GetProperty("422"), "application/problem+json"), StringComparison.Ordinal);
        Assert.EndsWith("/ProblemDetails", SchemaRef(responses.GetProperty("500"), "application/problem+json"), StringComparison.Ordinal);
        Assert.Equal(
            ["approvalId", "authorizationReason", "decision", "executed", "executionId", "outcome", "result", "riskLevel", "securityEventId"],
            PropertyNames(schemas.GetProperty("ToolExecutionResponse")));
        Assert.Equal(["found", "text"], PropertyNames(schemas.GetProperty("ToolResultResponse")));
        Assert.Equal(
            ["Executed", "HeldForReview", "Denied", "ArgumentsRejected", "ToolUnavailable", "ExecutionAuthorizationRejected", "ExecutionFailed", "InputContextRejected", "ApprovalRejected"],
            schemas.GetProperty("ToolExecutionOutcome").GetProperty("enum").EnumerateArray().Select(value => value.GetString()));
    }

    [Fact]
    public async Task ExecuteOperation_RequiresTheApiKey()
    {
        using var document = await GetDocumentAsync();

        var security = Execute(document).GetProperty("security").EnumerateArray().SelectMany(requirement => requirement.EnumerateObject().Select(scheme => scheme.Name));
        Assert.Equal(["ApiKey"], security);
    }

    [Fact]
    public async Task Document_NeverMentionsAGrantSignatureOrToolCredential()
    {
        var document = await _client.GetStringAsync("/swagger/v1/swagger.json");

        Assert.DoesNotContain("ExecutionGrant", document, StringComparison.Ordinal);
        Assert.DoesNotContain("\"signature\"", document, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("ExecutionScope", document, StringComparison.Ordinal);
    }

    private async Task<JsonDocument> GetDocumentAsync() =>
        JsonDocument.Parse(await _client.GetStringAsync("/swagger/v1/swagger.json"));

    private static JsonElement Execute(JsonDocument document) =>
        document.RootElement.GetProperty("paths").GetProperty("/api/v1/agent/tools/execute").GetProperty("post");

    private static string SchemaRef(JsonElement response, string mediaType) =>
        response.GetProperty("content").GetProperty(mediaType).GetProperty("schema").GetProperty("$ref").GetString()!;

    private static string[] PropertyNames(JsonElement schema) =>
        [.. schema.GetProperty("properties").EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal)];
}
