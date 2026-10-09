using System.Globalization;
using System.Text;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Abstractions.Security;

namespace AgentShield.Security.Normalization;

/// <summary>
/// Canonicalises untrusted input for detection. The original is preserved alongside; only the analysis copy changes.
/// </summary>
/// <remarks>
/// Steps, in order (each defeats a cheap way to write the same instruction differently):
/// <list type="number">
/// <item>Invisible format characters (Unicode category Cf: zero-width space/joiners, bidi controls, BOM, soft hyphen,
/// tag characters) are removed, so <c>ig&#x200B;nore</c> reads as <c>ignore</c>. So are the other invisible,
/// default-ignorable characters that are not Cf: variation selectors (U+FE00–U+FE0F, U+E0100–U+E01EF) and the
/// combining grapheme joiner (U+034F). They change no letter's meaning (at most an emoji's presentation) but split
/// words for keyword rules. Invalid UTF-16 (lone surrogates) and the noncharacter U+FFFE become U+FFFD so the next
/// step cannot fail; no other code point makes it fail.</item>
/// <item>Unicode NFKC folds compatibility forms onto their canonical characters: fullwidth <c>ｉｇｎｏｒｅ</c>, ligatures,
/// non-breaking and other typographic spaces.</item>
/// <item>Line endings become <c>\n</c>.</item>
/// <item>Outer whitespace is trimmed.</item>
/// </list>
/// Casing and inner whitespace are left alone: detectors match case-insensitively and across any whitespace, and
/// line structure matters to some rules. Look-alike letters from other scripts (Cyrillic <c>о</c> for Latin
/// <c>o</c>) are not folded here, only in the obfuscation detector's views.
/// <para>Removing tag characters and variation selectors also removes any text hidden in them (each tag character mirrors
/// an ASCII character; a run of selectors can carry bytes). That text is not lost to analysis: the obfuscation detector
/// reads it from the original input (<c>HiddenCharacterDecoding</c>).</para>
/// </remarks>
internal sealed class InputNormalizer : IInputNormalizer, ISingletonService
{
    /// <summary>U+FFFE, a noncharacter that <see cref="string.Normalize(NormalizationForm)"/> rejects.</summary>
    private const int RejectedByNormalize = 0xFFFE;

    public NormalizedInput Normalize(string input)
    {
        ArgumentNullException.ThrowIfNull(input);

        var normalized = RemoveFormatCharacters(input)
            .Normalize(NormalizationForm.FormKC)
            .ReplaceLineEndings("\n")
            .Trim();

        return new NormalizedInput(input, normalized);
    }

    private static string RemoveFormatCharacters(string input)
    {
        var builder = new StringBuilder(input.Length);

        // EnumerateRunes yields U+FFFD for invalid UTF-16, which string.Normalize would otherwise reject. The noncharacter
        // U+FFFE is the one valid code point it also rejects, in every form (D-18), so it becomes U+FFFD as well.
        foreach (var rune in input.EnumerateRunes())
        {
            if (rune.Value == RejectedByNormalize)
            {
                builder.Append(Rune.ReplacementChar.ToString());
            }
            else if (Rune.GetUnicodeCategory(rune) != UnicodeCategory.Format && !IsInvisibleSelector(rune.Value))
            {
                builder.Append(rune.ToString());
            }
        }

        return builder.ToString();
    }

    private static bool IsInvisibleSelector(int codePoint) =>
        codePoint is (>= 0xFE00 and <= 0xFE0F) or (>= 0xE0100 and <= 0xE01EF) or 0x034F;
}
