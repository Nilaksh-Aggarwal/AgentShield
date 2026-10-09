using System.Text.Json;
using AgentShield.ApiTests.Infrastructure;

namespace AgentShield.ApiTests.OpenApi;

/// <summary>The OpenAPI document describes the agent action authorization endpoint as it actually behaves.</summary>
public class AgentActionSwaggerTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task AuthorizeOperation_DocumentsExactlyTheStatusCodesItProduces()
    {
        using var document = await GetDocumentAsync();

        var statuses = Authorize(document).GetProperty("responses").EnumerateObject().Select(response => response.Name);
        Assert.Equal(["200", "400", "401", "403", "422", "429", "500"], statuses.Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task AuthorizeOperation_AcceptsOnlyTheDocumentedFields_AsJson()
    {
        using var document = await GetDocumentAsync();
        var schemas = document.RootElement.GetProperty("components").GetProperty("schemas");

        var content = Authorize(document).GetProperty("requestBody").GetProperty("content");
        Assert.Equal(["application/json"], content.EnumerateObject().Select(media => media.Name));
        Assert.Equal(["action", "agentId", "capability", "inputDecision", "tool"], PropertyNames(schemas.GetProperty("AuthorizeAgentActionRequest")));
    }

    [Fact]
    public async Task AuthorizeOperation_DescribesSuccessAsAnEnvelopedDecision_AndErrorsAsProblemDetails()
    {
        using var document = await GetDocumentAsync();
        var schemas = document.RootElement.GetProperty("components").GetProperty("schemas");
        var responses = Authorize(document).GetProperty("responses");

        Assert.EndsWith("AgentActionAuthorizationResponseApiResponse", SchemaRef(responses.GetProperty("200"), "application/json"), StringComparison.Ordinal);
        Assert.EndsWith("/ValidationProblemDetails", SchemaRef(responses.GetProperty("422"), "application/problem+json"), StringComparison.Ordinal);
        Assert.EndsWith("/ProblemDetails", SchemaRef(responses.GetProperty("500"), "application/problem+json"), StringComparison.Ordinal);
        Assert.Equal(["decision", "reason", "riskLevel", "securityEventId"], PropertyNames(schemas.GetProperty("AgentActionAuthorizationResponse")));
        Assert.Equal(
            ["Permitted", "HumanApprovalRequired", "InputHeldForReview", "UnknownAgent", "UnknownTool", "UnknownAction", "CapabilityMismatch", "CapabilityNotGranted", "CriticalActionDenied", "InputBlocked", "CallerNotBoundToAgent"],
            schemas.GetProperty("AgentActionReason").GetProperty("enum").EnumerateArray().Select(value => value.GetString()));
    }

    [Fact]
    public async Task AuthorizeOperation_RequiresTheApiKey()
    {
        using var document = await GetDocumentAsync();

        var security = Authorize(document).GetProperty("security").EnumerateArray().SelectMany(requirement => requirement.EnumerateObject().Select(scheme => scheme.Name));
        Assert.Equal(["ApiKey"], security);
    }

    private async Task<JsonDocument> GetDocumentAsync() =>
        JsonDocument.Parse(await _client.GetStringAsync("/swagger/v1/swagger.json"));

    private static JsonElement Authorize(JsonDocument document) =>
        document.RootElement.GetProperty("paths").GetProperty("/api/v1/agent/actions/authorize").GetProperty("post");

    private static string SchemaRef(JsonElement response, string mediaType) =>
        response.GetProperty("content").GetProperty(mediaType).GetProperty("schema").GetProperty("$ref").GetString()!;

    private static string[] PropertyNames(JsonElement schema) =>
        [.. schema.GetProperty("properties").EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal)];
}
