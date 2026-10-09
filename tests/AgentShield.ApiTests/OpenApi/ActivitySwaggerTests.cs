using System.Text.Json;
using AgentShield.ApiTests.Infrastructure;

namespace AgentShield.ApiTests.OpenApi;

/// <summary>The OpenAPI document describes the activity endpoint as it actually behaves.</summary>
public class ActivitySwaggerTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task ListOperation_DocumentsExactlyTheStatusCodesItProduces()
    {
        using var document = await GetDocumentAsync();

        var statuses = List(document).GetProperty("responses").EnumerateObject().Select(response => response.Name);
        Assert.Equal(["200", "400", "401", "403", "422", "429", "500"], statuses.Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task ListOperation_TakesOnlyTheBoundedQueryParameters_InCamelCase()
    {
        using var document = await GetDocumentAsync();

        var parameters = List(document).GetProperty("parameters").EnumerateArray().ToArray();
        Assert.Equal(["decision", "minRiskLevel", "page", "pageSize"], parameters.Select(parameter => parameter.GetProperty("name").GetString()).Order(StringComparer.Ordinal));
        Assert.All(parameters, parameter => Assert.Equal("query", parameter.GetProperty("in").GetString()));
        Assert.False(List(document).TryGetProperty("requestBody", out _));
    }

    [Fact]
    public async Task ListOperation_DescribesSuccessAsAnEnvelopedPage_OfMetadataOnlyItems()
    {
        using var document = await GetDocumentAsync();
        var schemas = document.RootElement.GetProperty("components").GetProperty("schemas");

        var success = List(document).GetProperty("responses").GetProperty("200").GetProperty("content").GetProperty("application/json");
        Assert.EndsWith("ActivityPageResponseApiResponse", success.GetProperty("schema").GetProperty("$ref").GetString(), StringComparison.Ordinal);
        Assert.Equal(
            ["agentAction", "aiAnalysis", "correlationId", "decision", "findings", "kind", "occurredAt", "risk", "securityEventId", "toolExecution"],
            PropertyNames(schemas.GetProperty("ActivityItemResponse")));
        Assert.Equal(["level", "score"], PropertyNames(schemas.GetProperty("ActivityRiskResponse")));
        Assert.Equal(["category", "code", "severity"], PropertyNames(schemas.GetProperty("ActivityFindingResponse")));
        Assert.Equal(["action", "agentId", "capability", "reason", "tool"], PropertyNames(schemas.GetProperty("ActivityAgentActionResponse")));
        Assert.Equal(["executed", "executionId", "outcome"], PropertyNames(schemas.GetProperty("ActivityToolExecutionResponse")));
        Assert.Equal(["Disabled", "Completed", "NotNeeded", "Incomplete"], EnumNames(schemas.GetProperty("ActivityAiStatus")));
        Assert.Equal(["InputAnalysis", "AgentActionAuthorization", "ToolExecution"], EnumNames(schemas.GetProperty("SecurityActivityKind")));
    }

    [Fact]
    public async Task SummaryOperation_DocumentsItsStatusCodes_AndACountsOnlySchema()
    {
        using var document = await GetDocumentAsync();
        var schemas = document.RootElement.GetProperty("components").GetProperty("schemas");
        var summary = document.RootElement.GetProperty("paths").GetProperty("/api/v1/activity/summary").GetProperty("get");

        Assert.Equal(["200", "401", "403", "429", "500"], summary.GetProperty("responses").EnumerateObject().Select(response => response.Name).Order(StringComparer.Ordinal));
        Assert.False(summary.TryGetProperty("parameters", out _));
        Assert.Equal(["decisions", "kinds", "newestOccurredAt", "oldestOccurredAt", "toolsExecuted", "totalCount"], PropertyNames(schemas.GetProperty("ActivitySummaryResponse")));
        Assert.Equal(["allow", "block", "review"], PropertyNames(schemas.GetProperty("ActivityDecisionCounts")));
        Assert.Equal(["agentActionAuthorization", "inputAnalysis", "toolExecution"], PropertyNames(schemas.GetProperty("ActivityKindCounts")));
    }

    private async Task<JsonDocument> GetDocumentAsync() =>
        JsonDocument.Parse(await _client.GetStringAsync("/swagger/v1/swagger.json"));

    private static JsonElement List(JsonDocument document) =>
        document.RootElement.GetProperty("paths").GetProperty("/api/v1/activity").GetProperty("get");

    private static string[] PropertyNames(JsonElement schema) =>
        [.. schema.GetProperty("properties").EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal)];

    private static string[] EnumNames(JsonElement schema) =>
        [.. schema.GetProperty("enum").EnumerateArray().Select(value => value.GetString() ?? string.Empty)];
}
