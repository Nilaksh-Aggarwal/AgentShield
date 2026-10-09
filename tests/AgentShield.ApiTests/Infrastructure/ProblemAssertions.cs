using System.Net;
using System.Text.Json;

namespace AgentShield.ApiTests.Infrastructure;

internal static class ProblemAssertions
{
    /// <summary>
    /// Asserts the response is RFC 9457 Problem Details carrying the AgentShield metadata, and returns the body.
    /// </summary>
    public static async Task<JsonElement> AssertProblemAsync(HttpResponseMessage response, HttpStatusCode status, string errorCode)
    {
        Assert.Equal(status, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var problem = document.RootElement.Clone();

        Assert.Equal((int)status, problem.GetProperty("status").GetInt32());
        Assert.False(string.IsNullOrWhiteSpace(problem.GetProperty("title").GetString()));
        Assert.Equal(errorCode, problem.GetProperty("errorCode").GetString());
        Assert.True(problem.TryGetProperty("timestamp", out _));

        var correlationId = problem.GetProperty("correlationId").GetString();
        Assert.Equal(Assert.Single(response.Headers.GetValues("X-Correlation-ID")), correlationId);

        return problem;
    }
}
