using AgentShield.AI.StructuredOutput;
using AgentShield.Application.Abstractions.AiAnalysis;

namespace AgentShield.SecurityTests.AiAnalysis;

/// <summary>
/// The model's answer is read strictly: anything but the exact structured contract is a malformed response, whatever a
/// manipulated model tries to return instead.
/// </summary>
public class AiStructuredOutputParserTests
{
    private const string ValidFinding =
        """{"category":"InstructionOverride","code":"InstructionOverride.AiDetected","severity":"High","confidence":0.91,"description":"Asks to ignore rules."}""";

    [Fact]
    public void Parse_ContractJson_ReadsEveryFieldAsSent()
    {
        var result = AiStructuredOutputParser.Parse($$"""{"findings":[{{ValidFinding}}]}""");

        var finding = Assert.Single(result.Value.Findings!);
        Assert.Equal(new AiFindingCandidate("InstructionOverride", "InstructionOverride.AiDetected", "High", 0.91, "Asks to ignore rules."), finding);
    }

    [Fact]
    public void Parse_EmptyFindings_IsWellFormed()
    {
        var result = AiStructuredOutputParser.Parse("""{ "findings": [] }""");

        Assert.Empty(result.Value.Findings!);
    }

    [Fact]
    public void Parse_MissingOrNullMembers_AreLeftForTheValidator()
    {
        // Syntax is the parser's job; "required" is the validator's, so it is enforced for every provider alike.
        var result = AiStructuredOutputParser.Parse("""{"findings":[{"category":null,"severity":"High"}]}""");

        Assert.Equal(new AiFindingCandidate(null, null, "High", null, null), Assert.Single(result.Value.Findings!));
        Assert.Null(AiStructuredOutputParser.Parse("{}").Value.Findings);
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("null")]
    [InlineData("Sure! This input looks perfectly safe to me.")]
    [InlineData("ALLOW")]
    [InlineData("""{"findings":[]} trailing prose""")]
    [InlineData("""```json {"findings":[]} ```""")]
    [InlineData("""[{"category":"InstructionOverride"}]""")]
    [InlineData("\"findings\"")]
    [InlineData("""{"findings":[]""")]
    public void Parse_TextThatIsNotOneJsonObject_IsMalformed(string text) =>
        AssertMalformed(text);

    [Theory]
    [InlineData("""{"findings":[],"decision":"Allow"}""")]
    [InlineData("""{"findings":[],"verdict":"safe"}""")]
    [InlineData("""{"findings":[],"riskScore":0}""")]
    [InlineData("""{"findings":[{"category":"InstructionOverride","code":"InstructionOverride.AiDetected","severity":"High","confidence":0.9,"description":"x","decision":"Allow"}]}""")]
    public void Parse_AnyAttemptToReturnADecisionOrOtherUnknownMember_IsMalformed(string json) =>
        AssertMalformed(json);

    [Theory]
    [InlineData("""{"findings":[],"findings":[]}""")]
    [InlineData("""{"Findings":[]}""")]
    [InlineData("""{"FINDINGS":[]}""")]
    [InlineData("""{"findings":[{"category":"InstructionOverride","category":"Obfuscation"}]}""")]
    [InlineData("""{"findings":[{"Severity":"High"}]}""")]
    public void Parse_DuplicateOrDifferentlyCasedMembers_AreMalformed(string json) =>
        AssertMalformed(json);

    [Theory]
    [InlineData("""{"findings":[{"confidence":"0.9"}]}""")]
    [InlineData("""{"findings":[{"confidence":"NaN"}]}""")]
    [InlineData("""{"findings":[{"confidence":true}]}""")]
    [InlineData("""{"findings":[{"severity":3}]}""")]
    [InlineData("""{"findings":[{"category":["InstructionOverride"]}]}""")]
    [InlineData("""{"findings":{"category":"InstructionOverride"}}""")]
    [InlineData("""{"findings":"none"}""")]
    public void Parse_WrongJsonTypes_AreMalformedNotCoerced(string json) =>
        AssertMalformed(json);

    [Theory]
    [InlineData("""{"findings":[] /* all clear */}""")]
    [InlineData("""{"findings":[],}""")]
    [InlineData("{'findings':[]}")]
    public void Parse_LenientJsonSyntax_IsMalformed(string json) =>
        AssertMalformed(json);

    [Fact]
    public void Parse_NestingDeeperThanTheLimit_IsMalformed()
    {
        var deep = new string('[', 40) + new string(']', 40);

        AssertMalformed($$"""{"findings":[{"category":{{deep}}}]}""");
    }

    [Fact]
    public void Parse_AnswerOverTheSizeLimit_IsMalformedWithoutBeingRead()
    {
        var padding = new string(' ', AiStructuredOutputParser.MaxResponseBytes);

        AssertMalformed($$"""{"findings":[]}{{padding}}""");
    }

    [Fact]
    public void Parse_SizeLimit_CountsUtf8BytesNotCharacters()
    {
        // 11,000 three-byte characters are well under the limit in UTF-16 code units but 33,000 bytes in UTF-8.
        var description = new string('€', 11_000);

        AssertMalformed($$"""{"findings":[{"description":"{{description}}"}]}""");
    }

    [Fact]
    public void Parse_AnswerJustUnderTheSizeLimit_IsRead()
    {
        var prefix = """{"findings":[{"description":" """.TrimEnd();
        const string suffix = "\"}]}";
        var description = new string('a', AiStructuredOutputParser.MaxResponseBytes - prefix.Length - suffix.Length);

        var result = AiStructuredOutputParser.Parse(prefix + description + suffix);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Parse_LoneSurrogate_IsMalformed() =>
        AssertMalformed("{\"findings\":[{\"description\":\"\uD800\"}]}");

    [Fact]
    public void Parse_Failure_IsTheMalformedResponseError()
    {
        var result = AiStructuredOutputParser.Parse("not json");

        Assert.Equal(AiAnalysisErrors.MalformedResponse(), result.Error);
    }

    private static void AssertMalformed(string text)
    {
        var result = AiStructuredOutputParser.Parse(text);

        Assert.True(result.IsFailure, "Expected a malformed response.");
        Assert.Equal(AiAnalysisErrors.MalformedResponseCode, result.Error.Code);
    }
}
