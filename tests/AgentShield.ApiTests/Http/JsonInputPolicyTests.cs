using System.Net;
using System.Text;
using System.Text.Json;
using AgentShield.ApiTests.Infrastructure;
using AgentShield.ApiTests.Probes;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AgentShield.ApiTests.Http;

/// <summary>
/// Strict JSON input policy (ADR 0009): every request body has exactly one interpretation, and anything
/// ambiguous is rejected as malformed (400) instead of being resolved silently.
/// </summary>
public class JsonInputPolicyTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private const string EchoRoute = "/api/v1/__probe/echo";
    private const string ValidatedRoute = "/api/v1/__probe/created";

    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task WellFormedRequest_IsParsedExactlyAsSent()
    {
        var response = await PostJsonAsync(
            EchoRoute,
            """{"input":"hello","decision":"Block","items":[{"displayName":"x"}],"metadata":{"tool":"search","args":[1,2]}}""");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var data = document.RootElement.GetProperty("data");
        Assert.Equal("hello", data.GetProperty("input").GetString());
        Assert.Equal("Block", data.GetProperty("decision").GetString());
        Assert.Equal("x", data.GetProperty("items")[0].GetProperty("displayName").GetString());
        Assert.Equal("search", data.GetProperty("metadata").GetProperty("tool").GetString());
    }

    [Theory]
    [InlineData("""{"input":"hello","input":"malicious"}""")]
    [InlineData("""{"input":"hello","decision":"Allow","decision":"Block"}""")]
    [InlineData("""{"items":[{"displayName":"a","displayName":"b"}]}""")]
    [InlineData("""{"metadata":{"tool":"search","tool":"shell"}}""")]
    [InlineData("""{"metadata":{"args":{"path":"/tmp","path":"/etc/passwd"}}}""")]
    public async Task DuplicateProperty_IsRejectedInsteadOfLastValueWinning(string body)
    {
        var response = await PostJsonAsync(EchoRoute, body);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.BadRequest, "Request.Malformed");
    }

    [Theory]
    [InlineData("""{"input":"hello","isAdmin":true}""")]
    [InlineData("""{"Input":"hello"}""")]
    [InlineData("""{"input":"hello","INPUT":"malicious"}""")]
    [InlineData("""{"items":[{"displayName":"a","role":"system"}]}""")]
    public async Task UnknownOrDifferentlyCasedProperty_IsRejectedInsteadOfIgnored(string body)
    {
        var response = await PostJsonAsync(EchoRoute, body);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.BadRequest, "Request.Malformed");
    }

    [Theory]
    [InlineData("999")]
    [InlineData("1")]
    [InlineData("\"1\"")]
    [InlineData("\"999\"")]
    [InlineData("\"-1\"")]
    [InlineData("\"block\"")]
    [InlineData("\"BLOCK\"")]
    [InlineData("\" Block\"")]
    [InlineData("\"Block, Sanitize\"")]
    [InlineData("\"Unknown\"")]
    [InlineData("\"\"")]
    [InlineData("true")]
    [InlineData("{}")]
    public async Task EnumValueOtherThanAnExactDeclaredName_IsRejected(string decision)
    {
        var response = await PostJsonAsync(EchoRoute, $$"""{"input":"hello","decision":{{decision}}}""");

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.BadRequest, "Request.Malformed");
    }

    [Theory]
    [InlineData("""{"input":"a",}""")]
    [InlineData("""{"input":"a" /* comment */}""")]
    [InlineData("{'input':'a'}")]
    [InlineData("""{"input":"a"} {"input":"b"}""")]
    [InlineData("""{"input":"\ud800"}""")]
    [InlineData("""{"input":42}""")]
    [InlineData("[]")]
    [InlineData("")]
    public async Task MalformedOrMistypedJson_IsRejected(string body)
    {
        var response = await PostJsonAsync(EchoRoute, body);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.BadRequest, "Request.Malformed");
    }

    [Theory]
    [InlineData(20, HttpStatusCode.OK)]
    [InlineData(100, HttpStatusCode.BadRequest)]
    public async Task NestingDepth_IsBounded(int depth, HttpStatusCode expected)
    {
        var nested = new string('[', depth) + new string(']', depth);

        var response = await PostJsonAsync(EchoRoute, $$"""{"input":"hello","metadata":{{nested}}}""");

        Assert.Equal(expected, response.StatusCode);
    }

    [Theory]
    [InlineData("""{"input":"hello","isAdmin":true}""")]
    [InlineData("""{"input":42}""")]
    [InlineData("""{"input":"hello","decision":"Maybe"}""")]
    [InlineData("""{"input":"hello","input":"again"}""")]
    public async Task RejectedJson_DoesNotLeakTypeNamesOrParserInternals(string body)
    {
        var response = await PostJsonAsync(EchoRoute, body);

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.BadRequest, "Request.Malformed");
        var text = problem.GetRawText();
        Assert.DoesNotContain("AgentShield", text, StringComparison.Ordinal);
        Assert.DoesNotContain(nameof(ProbeEchoRequest), text, StringComparison.Ordinal);
        Assert.DoesNotContain("System.", text, StringComparison.Ordinal);
        Assert.DoesNotContain("LineNumber", text, StringComparison.Ordinal);

        // The client still learns where the problem is: errors are keyed by JSON path.
        Assert.Contains(problem.GetProperty("errors").EnumerateObject(), error => error.Name.StartsWith('$'));
    }

    [Fact]
    public async Task NullForValidatedTextField_IsAValidationError()
    {
        var response = await PostJsonAsync(ValidatedRoute, """{"name":null,"priority":1}""");

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.UnprocessableEntity, "Validation.Failed");
        Assert.True(problem.GetProperty("errors").TryGetProperty("name", out _));
    }

    [Fact]
    public async Task NullForNonNullableNumber_IsMalformed()
    {
        var response = await PostJsonAsync(ValidatedRoute, """{"name":"x","priority":null}""");

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.BadRequest, "Request.Malformed");
    }

    [Fact]
    public void MvcAndHttpJsonOptions_ApplyTheSameReadPolicy()
    {
        var mvc = factory.Services.GetRequiredService<IOptions<Microsoft.AspNetCore.Mvc.JsonOptions>>().Value.JsonSerializerOptions;
        var http = factory.Services.GetRequiredService<IOptions<Microsoft.AspNetCore.Http.Json.JsonOptions>>().Value.SerializerOptions;

        foreach (var options in new[] { mvc, http })
        {
            Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ProbeEchoRequest>("""{"input":"a","input":"b"}""", options));
            Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ProbeEchoRequest>("""{"input":"a","extra":1}""", options));
            Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ProbeEchoRequest>("""{"decision":"Block, Sanitize"}""", options));
            Assert.Equal(ProbeDecision.Review, JsonSerializer.Deserialize<ProbeEchoRequest>("""{"decision":"Review"}""", options)!.Decision);
        }
    }

    private async Task<HttpResponseMessage> PostJsonAsync(string route, string body)
    {
        using var content = new StringContent(body, Encoding.UTF8, "application/json");
        return await _client.PostAsync(route, content);
    }
}
