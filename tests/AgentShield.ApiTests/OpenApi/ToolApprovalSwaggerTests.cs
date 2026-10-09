using System.Text.Json;
using AgentShield.ApiTests.Infrastructure;

namespace AgentShield.ApiTests.OpenApi;

/// <summary>
/// The OpenAPI document describes the approval endpoints as they behave (Milestone 13): deciding takes no body, so no client
/// value can be authoritative, and an approval is metadata only.
/// </summary>
public class ToolApprovalSwaggerTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Theory]
    [InlineData("/api/v1/agent/approvals/{approvalId}/approve")]
    [InlineData("/api/v1/agent/approvals/{approvalId}/deny")]
    public async Task DecideOperations_TakeNoBody_OnlyTheApprovalIdInThePath(string path)
    {
        using var document = await GetDocumentAsync();

        var operation = document.RootElement.GetProperty("paths").GetProperty(path).GetProperty("post");

        Assert.False(operation.TryGetProperty("requestBody", out _));
        Assert.Equal(["approvalId"], operation.GetProperty("parameters").EnumerateArray().Select(parameter => parameter.GetProperty("name").GetString()));
        Assert.Equal(["200", "401", "403", "404", "409", "429", "500"], operation.GetProperty("responses").EnumerateObject().Select(response => response.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task ApprovalSchema_IsMetadataOnly_WithoutArgumentsDigestOrClients()
    {
        using var document = await GetDocumentAsync();
        var schemas = document.RootElement.GetProperty("components").GetProperty("schemas");

        Assert.Equal(
            ["action", "agentId", "approvalId", "capability", "correlationId", "decidedAt", "expiresAt", "inputDecision", "reason", "requestedAt", "riskLevel", "securityEventId", "status", "tool"],
            schemas.GetProperty("ToolApprovalResponse").GetProperty("properties").EnumerateObject().Select(property => property.Name).Order(StringComparer.Ordinal));
        Assert.Equal(
            ["Pending", "Approved", "Denied", "Expired", "Used"],
            schemas.GetProperty("ToolApprovalStatus").GetProperty("enum").EnumerateArray().Select(value => value.GetString()));
        Assert.True(document.RootElement.GetProperty("paths").GetProperty("/api/v1/agent/approvals").TryGetProperty("get", out _));
    }

    private async Task<JsonDocument> GetDocumentAsync() =>
        JsonDocument.Parse(await _client.GetStringAsync("/swagger/v1/swagger.json"));
}
