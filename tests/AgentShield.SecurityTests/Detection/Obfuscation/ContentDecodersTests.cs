using System.Text;
using AgentShield.Security.Detection.Obfuscation;

namespace AgentShield.SecurityTests.Detection.Obfuscation;

public class ContentDecodersTests
{
    [Fact]
    public void DecodeBase64Segments_ValidTextSegment_IsDecodedInPlace()
    {
        var decoded = ContentDecoders.DecodeBase64Segments($"before {Base64("hidden words here")} after");

        Assert.Equal("before hidden words here after", decoded);
    }

    [Fact]
    public void DecodeBase64Segments_SeveralSegments_AreAllDecoded()
    {
        var decoded = ContentDecoders.DecodeBase64Segments($"{Base64("first segment!")}|{Base64("second segment?")}");

        Assert.Equal("first segment!|second segment?", decoded);
    }

    [Theory]
    [InlineData("aGVsbG8gd29ybGQh", "hello world!")] // no padding needed
    [InlineData("aGVsbG8gd29ybGQhIQ", "hello world!!")] // missing padding
    [InlineData("aGVsbG8gd29ybGQhIQ==", "hello world!!")] // with padding
    [InlineData("aGVsbG8gd29ybGQhIQ===", "hello world!!=")] // a third '=' is not padding: still decoded, the '=' kept (mutation testing)
    public void DecodeBase64Segments_PaddingVariants_AreDecoded(string input, string expected)
    {
        Assert.Equal(expected, ContentDecoders.DecodeBase64Segments(input));
    }

    [Fact]
    public void DecodeBase64Segments_UrlSafeAlphabet_IsDecoded()
    {
        const string text = "<<???>>>???>>>?~~~";
        var urlSafe = Base64(text).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        Assert.True(urlSafe.Contains('-', StringComparison.Ordinal) || urlSafe.Contains('_', StringComparison.Ordinal));

        Assert.Equal(text, ContentDecoders.DecodeBase64Segments(urlSafe));
    }

    [Theory]
    [InlineData("aGVsbG8gd29y")] // shorter than MinBase64Length
    [InlineData("internationalization")] // a long word: decodes to invalid UTF-8
    [InlineData("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ")] // PNG header: binary
    [InlineData("AAAAAAAAAAAAAAAAAAAAAAAA")] // decodes to NUL bytes: control characters
    [InlineData("aGVsbG8gd29ybGQhIQ=")] // inconsistent padding
    [InlineData("aGVsbG8gd29ybGQhI")] // impossible length (4n + 1)
    [InlineData("aGVs+G8gd29y_GQhIQ")] // mixes both alphabets
    [InlineData("no base64 here, only words")]
    public void DecodeBase64Segments_NotBase64Text_ReturnsNull(string input)
    {
        Assert.Null(ContentDecoders.DecodeBase64Segments(input));
    }

    [Theory]
    [InlineData("ignore%20previous", "ignore previous")]
    [InlineData("%49%47%4E%4F%52%45", "IGNORE")]
    [InlineData("caf%C3%A9", "café")] // multi-byte UTF-8
    [InlineData("a%2520b", "a%20b")] // one layer only
    [InlineData("C++%20rocks", "C++ rocks")] // '+' is kept
    public void DecodePercentEncoding_Escapes_AreDecodedOnce(string input, string expected)
    {
        Assert.Equal(expected, ContentDecoders.DecodePercentEncoding(input));
    }

    [Theory]
    [InlineData("100% sure")]
    [InlineData("50%off")]
    [InlineData("%ZZ is not an escape")]
    [InlineData("%")]
    [InlineData("%C3 alone is invalid UTF-8")]
    public void DecodePercentEncoding_NoValidEscape_ReturnsNull(string input)
    {
        Assert.Null(ContentDecoders.DecodePercentEncoding(input));
    }

    [Theory]
    [InlineData("&lt;|im_start|&gt;", "<|im_start|>")]
    [InlineData("&#105;gnore", "ignore")]
    [InlineData("&#x69;gnore", "ignore")]
    [InlineData("Tom &amp; Jerry", "Tom & Jerry")]
    public void DecodeHtmlEntities_References_AreDecoded(string input, string expected)
    {
        Assert.Equal(expected, ContentDecoders.DecodeHtmlEntities(input));
    }

    [Theory]
    [InlineData("Tom & Jerry")]
    [InlineData("no ampersand")]
    [InlineData("&notanentity")]
    public void DecodeHtmlEntities_NoReference_ReturnsNull(string input)
    {
        Assert.Null(ContentDecoders.DecodeHtmlEntities(input));
    }

    public static TheoryData<string> HostileInputs() => new()
    {
        Repeat("A", 32_000),
        Repeat("QUFB", 8_000), // valid Base64 of "AAA…"
        Repeat("%41", 10_666),
        Repeat("%25", 10_666),
        Repeat("&amp;", 6_400),
        Repeat("&#x10FFFF;", 3_200),
        Repeat("aGk=", 8_000), // many padded segments
    };

    [Theory]
    [MemberData(nameof(HostileInputs))]
    public void Decoders_NeverProduceLongerOutputThanInput(string input)
    {
        foreach (var decode in new Func<string, string?>[]
                 {
                     ContentDecoders.DecodeBase64Segments,
                     ContentDecoders.DecodePercentEncoding,
                     ContentDecoders.DecodeHtmlEntities,
                 })
        {
            var decoded = decode(input);
            Assert.True(decoded is null || decoded.Length <= input.Length);
        }
    }

    private static string Base64(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    private static string Repeat(string unit, int count) => string.Concat(Enumerable.Repeat(unit, count));
}
