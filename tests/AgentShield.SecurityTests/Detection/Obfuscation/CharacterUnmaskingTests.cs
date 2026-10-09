using AgentShield.Security.Detection.Obfuscation;

namespace AgentShield.SecurityTests.Detection.Obfuscation;

public class CharacterUnmaskingTests
{
    [Theory]
    [InlineData("i̸g̸n̸o̸r̸e̸", "ignore")]
    [InlineData("café naïve", "cafe naive")]
    [InlineData("plain", "plain")]
    public void RemoveCombiningMarks_StripsMarks(string input, string expected)
    {
        Assert.Equal(expected, CharacterUnmasking.RemoveCombiningMarks(input));
    }

    [Theory]
    [InlineData("іgnоrе", "ignore")] // Cyrillic і о е
    [InlineData("ΙGΝΟRΕ", "IGNORE")] // Greek capitals
    [InlineData("ignore", "ignore")]
    public void FoldLookAlikes_MapsToLatin(string input, string expected)
    {
        Assert.Equal(expected, CharacterUnmasking.FoldLookAlikes(input));
    }

    [Theory]
    [InlineData("i g n o r e", "ignore")]
    [InlineData("i g n o r e   p r e v", "ignore prev")] // a different gap is a word break
    [InlineData("i-g-n-o-r-e p-r-e-v", "ignore prev")]
    [InlineData("i g n o r e p r e v", "ignoreprev")] // one gap everywhere: words fuse
    [InlineData("i g  n o  r e  v", "ig no re v")] // gaps equally common: the shorter joins letters (mutation testing)
    [InlineData("i-g n-o r-e s", "i gn or es")] // equally common and long: the ordinally smaller (space) joins letters
    [InlineData("say i g n o r e now", "say ignore now")]
    [InlineData("a b c", "a b c")] // shorter than MinSpacedCharacters
    [InlineData("i    g    n    o", "i    g    n    o")] // gap longer than MaxSpacingGap
    [InlineData("normal words here", "normal words here")]
    public void CollapseSpacing_JoinsSpacedOutCharacters(string input, string expected)
    {
        Assert.Equal(expected, CharacterUnmasking.CollapseSpacing(input));
    }

    [Theory]
    [InlineData("1gn0r3", 'i', "ignore")]
    [InlineData("ru1es", 'l', "rules")]
    [InlineData("$y$t3m", 'i', "system")]
    [InlineData("stop!", 'i', "stop!")] // trailing '!' is punctuation
    [InlineData("h!dden", 'i', "hidden")]
    [InlineData("2024 and 42", 'i', "2024 and 42")] // numbers without letters are untouched
    [InlineData("@user", 'i', "auser")]
    public void SubstituteLeetspeak_ReplacesSubstitutesInsideWords(string input, char digitOneAs, string expected)
    {
        Assert.Equal(expected, CharacterUnmasking.SubstituteLeetspeak(input, digitOneAs));
    }

    [Fact]
    public void SubstituteLeetspeak_UnsupportedReadingOfOne_Throws()
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => CharacterUnmasking.SubstituteLeetspeak("x", 'x'));
    }

    [Theory]
    [InlineData("A perfectly ordinary sentence.")]
    [InlineData("Numbers like 2024 and 3.14 stay.")]
    public void Unmask_TextWithoutDisguise_ReturnsNull(string input)
    {
        Assert.Null(CharacterUnmasking.Unmask(input, 'i'));
    }

    [Fact]
    public void Unmask_CombinedDisguises_AreAllUndone()
    {
        Assert.Equal("ignore all", CharacterUnmasking.Unmask("1 g n о r 3   а l l", 'i'));
    }

    [Theory]
    [InlineData("a ")]
    [InlineData("1a ")]
    [InlineData("і")]
    [InlineData("é")]
    [InlineData("a.b-")]
    public void Unmask_NeverProducesLongerOutputThanInput(string unit)
    {
        var input = string.Concat(Enumerable.Repeat(unit, 32_000 / unit.Length));

        var unmasked = CharacterUnmasking.Unmask(input, 'i');

        Assert.True(unmasked is null || unmasked.Length <= input.Length);
    }
}
