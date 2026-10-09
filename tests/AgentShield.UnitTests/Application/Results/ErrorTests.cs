using AgentShield.Application.Common.Results;

namespace AgentShield.UnitTests.Application.Results;

public class ErrorTests
{
    [Fact]
    public void Validation_RecordsPropertyName()
    {
        var error = Error.Validation("Content", "Content is required.");

        Assert.Equal(ErrorType.Validation, error.Type);
        Assert.Equal("Validation.Invalid", error.Code);
        Assert.Equal("Content", error.PropertyName);
    }

    [Theory]
    [InlineData("", "message")]
    [InlineData("code", " ")]
    public void Constructor_RejectsBlankCodeOrMessage(string code, string message)
    {
        Assert.Throws<ArgumentException>(() => new Error(code, message, ErrorType.Unexpected));
    }

    [Fact]
    public void Equality_ComparesMetadataByContent()
    {
        var first = Error.Validation("Content", "Required.");
        var second = Error.Validation("Content", "Required.");
        var other = Error.Validation("Title", "Required.");

        Assert.Equal(first, second);
        Assert.NotEqual(first, other);
    }

    [Fact]
    public void WithMetadata_ReturnsNewErrorAndLeavesOriginalUnchanged()
    {
        var original = Error.Conflict("Item.Conflict", "Exists.");

        var enriched = original.WithMetadata("existingId", 7);

        Assert.Empty(original.Metadata);
        Assert.Equal(7, enriched.Metadata["existingId"]);
    }

    [Fact]
    public void Metadata_IsACopy_NotAffectedByLaterChangesToTheSource()
    {
        var source = new Dictionary<string, object?> { ["key"] = "before" };
        var error = new Error("Code", "Message", ErrorType.BusinessRule, source);

        source["key"] = "after";

        Assert.Equal("before", error.Metadata["key"]);
    }
}
