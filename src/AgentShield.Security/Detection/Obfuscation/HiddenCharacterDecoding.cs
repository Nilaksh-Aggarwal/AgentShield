using System.Buffers;
using System.Runtime.InteropServices;
using System.Text;

namespace AgentShield.Security.Detection.Obfuscation;

/// <summary>
/// Reads text hidden in invisible characters that the normaliser deletes before any rule runs: Unicode tag characters
/// (U+E0020–U+E007E, each an invisible copy of an ASCII character, "ASCII smuggling") and runs of variation selectors
/// (each one carries a byte of UTF-8: 16 in U+FE00–U+FE0F and 240 in U+E0100–U+E01EF, "emoji smuggling"). A model can
/// read both; a person and the rules on the normalised text cannot.
/// </summary>
/// <remarks>
/// <para>Works on the original input, because the normalised text no longer contains these characters. Produces two
/// readings, like the two readings of the digit 1 in <see cref="CharacterUnmasking"/>:</para>
/// <list type="bullet">
/// <item><see cref="HiddenText.InPlace"/>: the input with every hidden run decoded where it was and set off by a space
/// on both sides, so a payload glued to a visible word still starts and ends on a word boundary.</item>
/// <item><see cref="HiddenText.Alone"/>: only the decoded runs, joined without separators, for a payload spread over
/// several runs (e.g. one hidden character after each visible one). Only produced for two runs or more; with one run it
/// would add nothing to the in-place reading.</item>
/// </list>
/// <para>Legitimate uses are left alone or decode to harmless text. A single variation selector (emoji or text
/// presentation, an ideographic variant) is never decoded, only runs of at least
/// <see cref="ObfuscationLimits.MinVariationSelectorRun"/>, which legitimate text does not contain. Tag characters appear
/// legitimately only in emoji tag sequences (subdivision flags such as England's), which decode to a short code
/// (<c>gbeng</c>) that matches no rule; the language tag U+E0001 and the cancel tag U+E007F end a sequence and read as a
/// space.</para>
/// <para>One linear pass, never recursive: decoded text is not decoded again (hidden characters inside it are removed by
/// normalisation like any others). <see cref="HiddenText.Alone"/> is never longer than the input. A hidden run never
/// decodes to more UTF-16 units than it occupies (a tag character is two units and becomes one; a run of k selectors is
/// at least k units and becomes at most k), but gains two separators, so <see cref="HiddenText.InPlace"/> is at most
/// twice as long as the input.</para>
/// </remarks>
internal static class HiddenCharacterDecoding
{
    private const int LanguageTag = 0xE0001;
    private const int FirstTagCharacter = 0xE0020;
    private const int CancelTag = 0xE007F;
    private const int TagOffset = 0xE0000;

    private const int FirstSelector = 0xFE00;
    private const int LastSelector = 0xFE0F;
    private const int FirstSupplementSelector = 0xE0100;
    private const int LastSupplementSelector = 0xE01EF;

    /// <summary>
    /// Both readings of the text hidden in <paramref name="text"/>, or <see langword="null"/> when it hides none.
    /// </summary>
    /// <param name="text">The original input, before normalisation.</param>
    public static HiddenText? Reveal(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        // Every tag character and supplementary selector is encoded with the high surrogate U+DB40.
        if (text.AsSpan().IndexOf('\uDB40') < 0 && text.AsSpan().IndexOfAnyInRange('︀', '️') < 0)
        {
            return null;
        }

        var inPlace = new StringBuilder(text.Length);
        var alone = new StringBuilder();
        var run = new StringBuilder();
        var bytes = new List<byte>();
        var runs = 0;
        var index = 0;
        while (index < text.Length)
        {
            var kind = KindAt(text, index, out var codePoint, out var length);
            if (kind == HiddenKind.None)
            {
                inPlace.Append(text, index, length);
                index += length;
                continue;
            }

            var runStart = index;
            run.Clear();
            bytes.Clear();
            while (index < text.Length && KindAt(text, index, out codePoint, out length) == kind)
            {
                if (kind == HiddenKind.Tag)
                {
                    run.Append(codePoint is LanguageTag or CancelTag ? ' ' : (char)(codePoint - TagOffset));
                }
                else
                {
                    bytes.Add(SelectorByte(codePoint));
                }

                index += length;
            }

            if (kind == HiddenKind.Selector)
            {
                if (bytes.Count < ObfuscationLimits.MinVariationSelectorRun)
                {
                    // A lone selector is ordinary text (e.g. emoji presentation); normalisation removes it as before.
                    inPlace.Append(text, runStart, index - runStart);
                    continue;
                }

                // Invalid UTF-8 becomes U+FFFD, one per invalid byte at most.
                run.Append(Encoding.UTF8.GetString(CollectionsMarshal.AsSpan(bytes)));
            }

            inPlace.Append(' ').Append(run).Append(' ');
            alone.Append(run);
            runs++;
        }

        return runs == 0 ? null : new HiddenText(inPlace.ToString(), runs > 1 ? alone.ToString() : null);
    }

    private static HiddenKind KindAt(string text, int index, out int codePoint, out int length)
    {
        if (Rune.DecodeFromUtf16(text.AsSpan(index), out var rune, out length) != OperationStatus.Done)
        {
            // Invalid UTF-16 (a lone surrogate) is copied as it is; normalisation turns it into U+FFFD.
            codePoint = -1;
            length = 1;
            return HiddenKind.None;
        }

        codePoint = rune.Value;
        return codePoint switch
        {
            LanguageTag or (>= FirstTagCharacter and <= CancelTag) => HiddenKind.Tag,
            (>= FirstSelector and <= LastSelector) or (>= FirstSupplementSelector and <= LastSupplementSelector) => HiddenKind.Selector,
            _ => HiddenKind.None,
        };
    }

    private static byte SelectorByte(int codePoint) => codePoint <= LastSelector
        ? (byte)(codePoint - FirstSelector)
        : (byte)(codePoint - FirstSupplementSelector + 16);

    /// <summary>What a hidden run is made of.</summary>
    private enum HiddenKind
    {
        None,
        Tag,
        Selector,
    }

    /// <summary>The two readings of an input's hidden text. Analysis views only; never stored, logged or returned.</summary>
    /// <param name="InPlace">The input with each hidden run decoded in place, set off by spaces.</param>
    /// <param name="Alone">The decoded runs alone, joined; <see langword="null"/> when there is only one run.</param>
    public sealed record HiddenText(string InPlace, string? Alone);
}
