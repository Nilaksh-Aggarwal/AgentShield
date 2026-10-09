using System.Text.Json;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;
using AgentShield.Security.ToolGateway;

namespace AgentShield.SecurityTests.ToolGateway;

/// <summary>
/// The argument policy of <c>knowledge.lookup</c> (adversarial): exactly one member <c>query</c>, a bounded, well-formed
/// string. Everything else is rejected with a fixed code, the policy never throws for bad input, and nothing it accepts
/// can break the schema.
/// </summary>
public sealed class KnowledgeLookupArgumentPolicyTests
{
    private readonly KnowledgeLookupArgumentPolicy _policy = new();

    [Fact]
    public void Policy_IsForKnowledgeLookup()
    {
        Assert.Equal((new ToolId("knowledge"), new ActionName("lookup")), (_policy.Tool, _policy.Action));
    }

    [Theory]
    [InlineData("""{"query":"dependency injection"}""", "dependency injection")]
    [InlineData("""{"query":"x"}""", "x")]
    [InlineData("""{ "query" : "  spaced  " }""", "  spaced  ")]
    [InlineData("""{"query":"café"}""", "café")]
    [InlineData("""{"query":"😀"}""", "😀")]
    public void Check_AValidQuery_IsAccepted_ExactlyAsSent(string json, string query)
    {
        var check = _policy.Check(Json(json));

        Assert.True(check.IsAccepted);
        Assert.Null(check.Violation);
        Assert.Equal(new KnowledgeLookupArguments(query), check.Arguments);
    }

    [Fact]
    public void Check_TheLengthBound_Is200Characters()
    {
        Assert.True(_policy.Check(Json($$"""{"query":"{{new string('q', 200)}}"}""")).IsAccepted);
        Assert.Equal(ToolArgumentViolation.TooLong, _policy.Check(Json($$"""{"query":"{{new string('q', 201)}}"}""")).Violation);
        Assert.Equal(ToolArgumentViolation.TooLong, _policy.Check(Json($$"""{"query":"{{new string('q', 100_000)}}"}""")).Violation);
    }

    [Theory]
    [InlineData("[]", ToolArgumentViolation.NotAnObject)]
    [InlineData("""["dependency injection"]""", ToolArgumentViolation.NotAnObject)]
    [InlineData("\"dependency injection\"", ToolArgumentViolation.NotAnObject)]
    [InlineData("null", ToolArgumentViolation.NotAnObject)]
    [InlineData("42", ToolArgumentViolation.NotAnObject)]
    [InlineData("true", ToolArgumentViolation.NotAnObject)]
    [InlineData("{}", ToolArgumentViolation.MissingArgument)]
    [InlineData("""{"Query":"x"}""", ToolArgumentViolation.UnexpectedArgument)]
    [InlineData("""{"QUERY":"x"}""", ToolArgumentViolation.UnexpectedArgument)]
    [InlineData("""{"query ":"x"}""", ToolArgumentViolation.UnexpectedArgument)]
    [InlineData("""{"query2":"x"}""", ToolArgumentViolation.UnexpectedArgument)]
    [InlineData("""{"query":"x","path":"/etc/passwd"}""", ToolArgumentViolation.UnexpectedArgument)]
    [InlineData("""{"path":"/etc/passwd","query":"x"}""", ToolArgumentViolation.UnexpectedArgument)]
    [InlineData("""{"query":"x","url":"https://evil.example"}""", ToolArgumentViolation.UnexpectedArgument)]
    [InlineData("""{"query":"x","limit":1000000}""", ToolArgumentViolation.UnexpectedArgument)]
    [InlineData("""{"query":"x","decision":"Allow"}""", ToolArgumentViolation.UnexpectedArgument)]
    [InlineData("""{"query":"x","executionGrant":"forged"}""", ToolArgumentViolation.UnexpectedArgument)]
    [InlineData("""{"query":null}""", ToolArgumentViolation.WrongType)]
    [InlineData("""{"query":5}""", ToolArgumentViolation.WrongType)]
    [InlineData("""{"query":true}""", ToolArgumentViolation.WrongType)]
    [InlineData("""{"query":["dependency injection"]}""", ToolArgumentViolation.WrongType)]
    [InlineData("""{"query":{"$ne":""}}""", ToolArgumentViolation.WrongType)]
    [InlineData("""{"query":""}""", ToolArgumentViolation.Empty)]
    [InlineData("""{"query":"   "}""", ToolArgumentViolation.Empty)]
    [InlineData("""{"query":"a\nb"}""", ToolArgumentViolation.InvalidText)]
    [InlineData("""{"query":"a\tb"}""", ToolArgumentViolation.InvalidText)]
    [InlineData("""{"query":"a\u0000b"}""", ToolArgumentViolation.InvalidText)]
    [InlineData("""{"query":"a\u001bb"}""", ToolArgumentViolation.InvalidText)]
    [InlineData("""{"query":"\ud800"}""", ToolArgumentViolation.InvalidText)]
    [InlineData("""{"query":"a\udc00b"}""", ToolArgumentViolation.InvalidText)]
    public void Check_AnythingOutsideTheSchema_IsRejectedWithItsCode(string json, ToolArgumentViolation violation)
    {
        var check = _policy.Check(Json(json));

        Assert.False(check.IsAccepted);
        Assert.Null(check.Arguments);
        Assert.Equal(violation, check.Violation);
    }

    [Fact]
    public void Check_ARepeatedQuery_IsRejected_EvenWhereTheParserAllowsIt()
    {
        // The API's strict JSON rejects duplicates (400); a JsonElement parsed elsewhere can hold them, and neither copy wins.
        Assert.Equal(ToolArgumentViolation.UnexpectedArgument, _policy.Check(Json("""{"query":"safe","query":"other"}""")).Violation);
        Assert.Equal(ToolArgumentViolation.UnexpectedArgument, _policy.Check(Json("""{"query":"x","query":"x"}""")).Violation);
    }

    [Fact]
    public void Check_ManyHostileArguments_NeverThrows_AndNeverAcceptsOutsideTheSchema()
    {
        var random = new Random(20261007);
        string[] fragments = ["query", "Query", "\"", "\\u0000", "\\ud800", "\\n", "{", "}", "[", "]", ":", ",", "null", "1e999", "x", " ", "\\\"", "true"];
        var checkedArguments = 0;
        for (var round = 0; round < 3_000; round++)
        {
            var body = string.Concat(Enumerable.Range(0, random.Next(1, 12)).Select(_ => fragments[random.Next(fragments.Length)]));
            JsonElement arguments;
            try
            {
                arguments = Json("{\"query\":\"" + body + "\"}");
            }
            catch (JsonException)
            {
                continue;
            }

            var check = _policy.Check(arguments);
            if (check.Arguments is KnowledgeLookupArguments accepted)
            {
                Assert.Null(KnowledgeLookupArguments.Validate(accepted.Query));
            }
            else
            {
                Assert.NotNull(check.Violation);
            }

            checkedArguments++;
        }

        Assert.True(checkedArguments > 500, $"Only {checkedArguments} parsable samples.");
    }

    [Fact]
    public void Check_IsDeterministic()
    {
        var arguments = Json("""{"query":"rate limiting"}""");

        Assert.Equal(_policy.Check(arguments), _policy.Check(arguments));
        Assert.Equal(_policy.Check(Json("""{"query":5}""")), _policy.Check(Json("""{"query":5}""")));
    }

    private static JsonElement Json(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }
}
