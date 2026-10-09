using AgentShield.Application.Agents.AuthorizeAgentAction;
using AgentShield.Domain.Policy;

namespace AgentShield.UnitTests.Application.Agents;

public sealed class AuthorizeAgentActionRequestValidatorTests
{
    private readonly AuthorizeAgentActionRequestValidator _validator = new();

    [Theory]
    [InlineData(null)]
    [InlineData(SecurityDecision.Allow)]
    [InlineData(SecurityDecision.Review)]
    [InlineData(SecurityDecision.Block)]
    public void Validate_WellFormedRequest_Passes(SecurityDecision? inputDecision)
    {
        var result = _validator.Validate(new AuthorizeAgentActionRequest("support-agent", "email", "send", "email:send", inputDecision));

        Assert.True(result.IsValid);
    }

    [Theory]
    [InlineData(null, "email", "send", "email:send", "AgentId")]
    [InlineData("", "email", "send", "email:send", "AgentId")]
    [InlineData("support-agent", null, "send", "email:send", "Tool")]
    [InlineData("support-agent", "email", "", "email:send", "Action")]
    [InlineData("support-agent", "email", "send", null, "Capability")]
    public void Validate_MissingField_FailsOnThatField(string? agentId, string? tool, string? action, string? capability, string property)
    {
        var result = _validator.Validate(new AuthorizeAgentActionRequest(agentId, tool, action, capability, null));

        var error = Assert.Single(result.Errors);
        Assert.Equal(property, error.PropertyName);
    }

    [Theory]
    [InlineData("Support-Agent", "email", "send", "email:send", "AgentId", AuthorizeAgentActionRequestValidator.InvalidNameCode)]
    [InlineData("support agent", "email", "send", "email:send", "AgentId", AuthorizeAgentActionRequestValidator.InvalidNameCode)]
    [InlineData("support-agent", "EMAIL", "send", "email:send", "Tool", AuthorizeAgentActionRequestValidator.InvalidNameCode)]
    [InlineData("support-agent", "email ", "send", "email:send", "Tool", AuthorizeAgentActionRequestValidator.InvalidNameCode)]
    [InlineData("support-agent", "email", "send*", "email:send", "Action", AuthorizeAgentActionRequestValidator.InvalidNameCode)]
    [InlineData("support-agent", "email", "send", "email:*", "Capability", AuthorizeAgentActionRequestValidator.InvalidCapabilityCode)]
    [InlineData("support-agent", "email", "send", "*", "Capability", AuthorizeAgentActionRequestValidator.InvalidCapabilityCode)]
    [InlineData("support-agent", "email", "send", "Email:Send", "Capability", AuthorizeAgentActionRequestValidator.InvalidCapabilityCode)]
    [InlineData("support-agent", "email", "send", "email:send:all", "Capability", AuthorizeAgentActionRequestValidator.InvalidCapabilityCode)]
    public void Validate_InexactName_FailsOnThatFieldWithItsCode(string agentId, string tool, string action, string capability, string property, string code)
    {
        var result = _validator.Validate(new AuthorizeAgentActionRequest(agentId, tool, action, capability, null));

        var error = Assert.Single(result.Errors);
        Assert.Equal((property, code), (error.PropertyName, error.ErrorCode));
    }

    [Fact]
    public void Validate_LookalikeAndOverlongNames_Fail()
    {
        var cyrillic = "em" + (char)0x0430 + "il";
        var overlong = new string('a', 65);

        var result = _validator.Validate(new AuthorizeAgentActionRequest(overlong, cyrillic, "send", "email:send", null));

        Assert.Equal(["AgentId", "Tool"], result.Errors.Select(error => error.PropertyName));
    }

    [Fact]
    public void Validate_InexactNames_ExplainTheExpectedFormat_PerField()
    {
        // Mutation testing (M10): emptied messages went unnoticed. The 422 must tell the caller what an exact name looks like.
        var result = _validator.Validate(new AuthorizeAgentActionRequest("A", "B", "C", "D", null));

        var messages = result.Errors.ToDictionary(error => error.PropertyName, error => error.ErrorMessage);
        Assert.StartsWith("'Agent Id' must be 1-64 characters of lower-case letters", messages["AgentId"], StringComparison.Ordinal);
        Assert.StartsWith("'Tool' must be 1-64 characters of lower-case letters", messages["Tool"], StringComparison.Ordinal);
        Assert.StartsWith("'Action' must be 1-64 characters of lower-case letters", messages["Action"], StringComparison.Ordinal);
        Assert.StartsWith("'Capability' must be 'resource:operation'", messages["Capability"], StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_RejectedValues_AreNeverEchoedInTheMessages()
    {
        const string Marker = "Zq7Echo";

        var result = _validator.Validate(new AuthorizeAgentActionRequest(Marker, Marker, Marker, Marker + ":X", null));

        Assert.Equal(4, result.Errors.Count);
        Assert.All(result.Errors, error => Assert.DoesNotContain(Marker, error.ErrorMessage, StringComparison.Ordinal));
    }
}
