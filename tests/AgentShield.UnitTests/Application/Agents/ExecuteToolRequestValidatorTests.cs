using System.Text.Json;
using AgentShield.Application.Agents.ExecuteTool;
using AgentShield.Domain.Policy;

namespace AgentShield.UnitTests.Application.Agents;

/// <summary>
/// The tool gateway's request validation (422): exact names, a capability, and an arguments object. What the object holds is
/// the argument policy's decision, not the validator's. Messages describe the format, never the value.
/// </summary>
public sealed class ExecuteToolRequestValidatorTests
{
    private readonly ExecuteToolRequestValidator _validator = new();

    [Fact]
    public void Validate_AWellFormedRequest_Passes_WhateverTheArgumentsObjectHolds()
    {
        Assert.True(_validator.Validate(Request()).IsValid);
        Assert.True(_validator.Validate(Request(arguments: "{}")).IsValid);
        Assert.True(_validator.Validate(Request(arguments: """{"anything":[1,2,3],"query":null}""")).IsValid);
        Assert.True(_validator.Validate(Request() with { InputDecision = SecurityDecision.Block }).IsValid);
    }

    [Theory]
    [InlineData(null, "lookup", "knowledge:read", "Tool")]
    [InlineData("", "lookup", "knowledge:read", "Tool")]
    [InlineData("knowledge", null, "knowledge:read", "Action")]
    [InlineData("knowledge", "", "knowledge:read", "Action")]
    [InlineData("knowledge", "lookup", null, "Capability")]
    [InlineData("knowledge", "lookup", "", "Capability")]
    public void Validate_AMissingName_FailsOnThatField(string? tool, string? action, string? capability, string field)
    {
        var result = _validator.Validate(new ExecuteToolRequest(tool, action, capability, Json("""{"query":"x"}"""), null));

        var error = Assert.Single(result.Errors);
        Assert.Equal(field, error.PropertyName);
    }

    [Theory]
    [InlineData("Knowledge", "lookup", "knowledge:read", "Tool", ExecuteToolRequestValidator.InvalidNameCode)]
    [InlineData(" knowledge", "lookup", "knowledge:read", "Tool", ExecuteToolRequestValidator.InvalidNameCode)]
    [InlineData("knоwledge", "lookup", "knowledge:read", "Tool", ExecuteToolRequestValidator.InvalidNameCode)]
    [InlineData("knowledge*", "lookup", "knowledge:read", "Tool", ExecuteToolRequestValidator.InvalidNameCode)]
    [InlineData("knowledge", "LOOKUP", "knowledge:read", "Action", ExecuteToolRequestValidator.InvalidNameCode)]
    [InlineData("knowledge", "look up", "knowledge:read", "Action", ExecuteToolRequestValidator.InvalidNameCode)]
    [InlineData("knowledge", "lookup", "knowledge:*", "Capability", ExecuteToolRequestValidator.InvalidCapabilityCode)]
    [InlineData("knowledge", "lookup", "knowledge", "Capability", ExecuteToolRequestValidator.InvalidCapabilityCode)]
    [InlineData("knowledge", "lookup", "Knowledge:Read", "Capability", ExecuteToolRequestValidator.InvalidCapabilityCode)]
    public void Validate_AnInexactName_FailsWithTheFormat_NeverTheValue(string tool, string action, string capability, string field, string code)
    {
        var result = _validator.Validate(new ExecuteToolRequest(tool, action, capability, Json("""{"query":"x"}"""), null));

        var error = Assert.Single(result.Errors);
        Assert.Equal((field, code), (error.PropertyName, error.ErrorCode));
        Assert.DoesNotContain(tool == "knowledge" ? (action == "lookup" ? capability : action) : tool, error.ErrorMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("Tool", "'Tool' must be 1-64 characters of lower-case letters, digits, '.', '_' and '-', starting with a letter or digit.")]
    [InlineData("Action", "'Action' must be 1-64 characters of lower-case letters, digits, '.', '_' and '-', starting with a letter or digit.")]
    [InlineData("Capability", "'Capability' must be 'resource:operation': two parts of lower-case letters, digits, '_' and '-', at most 64 characters in all.")]
    public void Validate_AnInexactName_DescribesTheFormatInFull(string field, string message)
    {
        var request = field switch
        {
            "Tool" => Request() with { Tool = "Zq7Tool" },
            "Action" => Request() with { Action = "Zq7Action" },
            _ => Request() with { Capability = "Zq7:Cap" },
        };

        var error = Assert.Single(_validator.Validate(request).Errors);

        Assert.Equal((field, message), (error.PropertyName, error.ErrorMessage));
    }

    [Fact]
    public void Validate_MissingOrNullArguments_Fail()
    {
        var result = _validator.Validate(new ExecuteToolRequest("knowledge", "lookup", "knowledge:read", null, null));

        var error = Assert.Single(result.Errors);
        Assert.Equal("Arguments", error.PropertyName);
    }

    [Theory]
    [InlineData("null")]
    [InlineData("[]")]
    [InlineData("""["dependency injection"]""")]
    [InlineData("\"dependency injection\"")]
    [InlineData("42")]
    [InlineData("true")]
    public void Validate_ArgumentsThatAreNotAnObject_FailWithoutQuotingThem(string arguments)
    {
        var result = _validator.Validate(Request(arguments: arguments));

        var error = Assert.Single(result.Errors);
        Assert.Equal(("Arguments", ExecuteToolRequestValidator.InvalidArgumentsCode, "'Arguments' must be a JSON object."), (error.PropertyName, error.ErrorCode, error.ErrorMessage));
    }

    private static ExecuteToolRequest Request(string arguments = """{"query":"dependency injection"}""") =>
        new("knowledge", "lookup", "knowledge:read", Json(arguments), null);

    private static JsonElement Json(string json)
    {
        using var document = JsonDocument.Parse(json);
        return document.RootElement.Clone();
    }
}
