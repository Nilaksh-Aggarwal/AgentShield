using AgentShield.Domain.Agents;

namespace AgentShield.UnitTests.Domain.Agents;

/// <summary>
/// The one spelling of every agent, tool, action and capability name: exact lower-case ASCII, nothing normalised, so a
/// name cannot pass a check under one reading and be acted on under another.
/// </summary>
public sealed class AgentIdentifierTests
{
    public static TheoryData<string> ValidNames => new() { "a", "7", "support-agent", "email", "x.y_z-1", new string((char)0x61, AgentIdentifiers.MaxLength) };

    public static TheoryData<string?> InvalidNames => new()
    {
        null,
        string.Empty,
        " ",
        " email",
        "email ",
        "Email",
        "EMAIL",
        "e mail",
        "email\n",
        "email\t",
        "-email",
        ".email",
        "_email",
        "email:send",
        "email/send",
        "../etc",
        "*",
        new string('a', AgentIdentifiers.MaxLength + 1),
        "em" + (char)0x0430 + "il", // Cyrillic a
        "emai" + (char)0x0456, // Cyrillic i
        "email" + (char)0x200B, // zero-width space
        (char)0xFF45 + "mail", // full-width e
        "e" + (char)0x0301 + "mail", // combining accent
        (char)0x00E9 + "mail", // precomposed accent
    };

    public static TheoryData<string> ValidCapabilities => new() { "a:b", "email:send", "data_x:read-all", "x1:y2", "aaaa:" + new string((char)0x62, AgentIdentifiers.MaxLength - 5) };

    public static TheoryData<string?> InvalidCapabilities => new()
    {
        null,
        string.Empty,
        "email",
        ":send",
        "email:",
        ":",
        "email:send:now",
        "email::send",
        "Email:send",
        "email:Send",
        "email:*",
        "*:*",
        "email.x:send",
        "email:send.all",
        "email :send",
        "email: send",
        "-email:send",
        "email:-send",
        "aaaa:" + new string('b', AgentIdentifiers.MaxLength - 4),
        "email" + (char)0xFF1A + "send", // full-width colon
        "email:se" + (char)0x0301 + "nd",
        "emai" + (char)0x0456 + ":send",
    };

    [Theory]
    [MemberData(nameof(ValidNames))]
    public void IsValidName_ExactLowerCaseAsciiNames_AreAccepted_ByEveryNameType(string value)
    {
        Assert.True(AgentIdentifiers.IsValidName(value));
        Assert.Equal(value, new AgentId(value).Value);
        Assert.Equal(value, new ToolId(value).Value);
        Assert.Equal(value, new ActionName(value).Value);
    }

    [Theory]
    [MemberData(nameof(InvalidNames))]
    public void IsValidName_CasingWhitespaceLookalikesSeparatorsAndOverlongNames_AreRejected_ByEveryNameType(string? value)
    {
        Assert.False(AgentIdentifiers.IsValidName(value));
        Assert.ThrowsAny<ArgumentException>(() => new AgentId(value!));
        Assert.ThrowsAny<ArgumentException>(() => new ToolId(value!));
        Assert.ThrowsAny<ArgumentException>(() => new ActionName(value!));
    }

    [Theory]
    [MemberData(nameof(ValidCapabilities))]
    public void IsValidCapability_ResourceColonOperation_IsAccepted(string value)
    {
        Assert.True(AgentIdentifiers.IsValidCapability(value));
        Assert.Equal(value, new Capability(value).Value);
    }

    [Theory]
    [MemberData(nameof(InvalidCapabilities))]
    public void IsValidCapability_WildcardsMissingPartsExtraColonsCasingAndLookalikes_AreRejected(string? value)
    {
        Assert.False(AgentIdentifiers.IsValidCapability(value));
        Assert.ThrowsAny<ArgumentException>(() => new Capability(value!));
    }

    [Fact]
    public void Constructors_RejectedValue_IsNeverQuotedInTheException()
    {
        // The value is caller-supplied until it passes; an exception message may reach a log.
        const string Marker = "Zq7MarkerName";

        Assert.DoesNotContain(Marker, Assert.Throws<ArgumentException>(() => new AgentId(Marker)).Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Marker, Assert.Throws<ArgumentException>(() => new ToolId(Marker)).Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Marker, Assert.Throws<ArgumentException>(() => new ActionName(Marker)).Message, StringComparison.Ordinal);
        Assert.DoesNotContain(Marker, Assert.Throws<ArgumentException>(() => new Capability(Marker + ":x")).Message, StringComparison.Ordinal);
    }

    [Fact]
    public void Names_AreEqualOnlyForTheSameTypeAndExactValue()
    {
        Assert.Equal(new Capability("email:send"), new Capability("email:send"));
        Assert.NotEqual(new Capability("email:send"), new Capability("email:read"));
        Assert.Equal(new AgentId("support-agent"), new AgentId("support-agent"));

        // A tool and an action with the same text are different things.
        Assert.False(new ToolId("read").Equals(new ActionName("read")));
        Assert.Equal("email", new ToolId("email").ToString());
    }
}
