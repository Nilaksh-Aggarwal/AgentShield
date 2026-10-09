using System.Collections.Frozen;
using System.Globalization;
using System.Text;

namespace AgentShield.Security.Detection.Obfuscation;

/// <summary>
/// Undoes character-level disguises that keep text readable to a model but defeat keyword rules. Produces an analysis
/// view only: the result is deliberately lossy (diacritics and non-Latin letters are folded), which is why it is never
/// the normalised input itself.
/// </summary>
/// <remarks>
/// Steps, in order, each one linear and never lengthening the text:
/// <list type="number">
/// <item>Combining marks are removed (<c>i̸g̸n̸o̸r̸e̸</c>, "Zalgo" text, accents).</item>
/// <item>Look-alike letters from Cyrillic, Greek and Armenian, and a few Latin variants, fold to the Latin letter they
/// imitate (<c>іgnоrе</c> with Cyrillic і, о, е).</item>
/// <item>Spaced-out characters are joined (<c>i g n o r e</c>, <c>i.g.n.o.r.e</c>). Within one run, the most common gap
/// is the letter gap and is removed; any other gap is a word break and becomes one space
/// (<c>i g n o r e / p r e v</c> → <c>ignore prev</c>). When every gap is the same, the words fuse
/// (<c>ignoreprevious…</c>); compact rules in <see cref="ObfuscationDetector"/> cover that case.</item>
/// <item>Digit and symbol substitutions inside words become letters (<c>1gn0r3</c> → <c>ignore</c>), only in words that
/// also contain a letter, so plain numbers are untouched. <c>1</c> reads as <c>i</c> or <c>l</c>; the caller
/// chooses.</item>
/// </list>
/// </remarks>
internal static class CharacterUnmasking
{
    private static readonly FrozenDictionary<char, char> LookAlikes = new Dictionary<char, char>
    {
        // Cyrillic
        ['а'] = 'a', ['е'] = 'e', ['о'] = 'o', ['р'] = 'p', ['с'] = 'c', ['у'] = 'y', ['х'] = 'x', ['і'] = 'i',
        ['ј'] = 'j', ['ѕ'] = 's', ['ԁ'] = 'd', ['ԛ'] = 'q', ['ԝ'] = 'w', ['һ'] = 'h', ['ӏ'] = 'l', ['к'] = 'k',
        ['А'] = 'A', ['В'] = 'B', ['Е'] = 'E', ['К'] = 'K', ['М'] = 'M', ['Н'] = 'H', ['О'] = 'O', ['Р'] = 'P',
        ['С'] = 'C', ['Т'] = 'T', ['Х'] = 'X', ['У'] = 'Y', ['І'] = 'I', ['Ј'] = 'J', ['Ѕ'] = 'S', ['Ԛ'] = 'Q',
        ['Ԝ'] = 'W', ['Һ'] = 'H', ['Ӏ'] = 'l',

        // Greek
        ['α'] = 'a', ['ο'] = 'o', ['ι'] = 'i', ['ε'] = 'e', ['ρ'] = 'p', ['τ'] = 't', ['υ'] = 'u', ['ν'] = 'v',
        ['κ'] = 'k', ['χ'] = 'x', ['Α'] = 'A', ['Β'] = 'B', ['Ε'] = 'E', ['Ζ'] = 'Z', ['Η'] = 'H', ['Ι'] = 'I',
        ['Κ'] = 'K', ['Μ'] = 'M', ['Ν'] = 'N', ['Ο'] = 'O', ['Ρ'] = 'P', ['Τ'] = 'T', ['Υ'] = 'Y', ['Χ'] = 'X',

        // Armenian and Latin variants
        ['օ'] = 'o', ['ս'] = 'u', ['ɑ'] = 'a', ['ı'] = 'i', ['ɡ'] = 'g', ['ʟ'] = 'l',
    }.ToFrozenDictionary();

    /// <summary>
    /// Applies every step. Returns <see langword="null"/> when the text contains none of these disguises.
    /// </summary>
    /// <param name="text">Normalised text.</param>
    /// <param name="digitOneAs">The letter <c>1</c> stands for: <c>'i'</c> or <c>'l'</c>.</param>
    public static string? Unmask(string text, char digitOneAs)
    {
        ArgumentNullException.ThrowIfNull(text);

        var unmasked = SubstituteLeetspeak(CollapseSpacing(FoldLookAlikes(RemoveCombiningMarks(text))), digitOneAs);
        return string.Equals(unmasked, text, StringComparison.Ordinal) ? null : unmasked;
    }

    public static string RemoveCombiningMarks(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        // Precomposed letters (é, ï) carry their marks only after decomposition, so any non-ASCII text is decomposed.
        if (Ascii.IsValid(text))
        {
            return text;
        }

        var decomposed = text.Normalize(NormalizationForm.FormD);
        var builder = new StringBuilder(decomposed.Length);
        foreach (var c in decomposed)
        {
            if (!IsCombiningMark(c))
            {
                builder.Append(c);
            }
        }

        return builder.ToString().Normalize(NormalizationForm.FormC);
    }

    public static string FoldLookAlikes(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        if (!text.Any(LookAlikes.ContainsKey))
        {
            return text;
        }

        return string.Create(text.Length, text, static (span, source) =>
        {
            for (var i = 0; i < source.Length; i++)
            {
                span[i] = LookAlikes.TryGetValue(source[i], out var latin) ? latin : source[i];
            }
        });
    }

    public static string CollapseSpacing(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        StringBuilder? output = null;
        var copiedUpTo = 0;
        var gaps = new List<Range>();
        var index = 0;
        while (index < text.Length)
        {
            if (!IsSingleCharacterAt(text, index))
            {
                index++;
                continue;
            }

            var runStart = index;
            var last = index;
            gaps.Clear();
            while (TryFindNextSpacedCharacter(text, last, out var gap, out var next))
            {
                gaps.Add(gap);
                last = next;
            }

            index = last + 1;
            if (gaps.Count + 1 < ObfuscationLimits.MinSpacedCharacters)
            {
                continue;
            }

            output ??= new StringBuilder(text.Length);
            output.Append(text, copiedUpTo, runStart - copiedUpTo);
            AppendCollapsedRun(output, text, runStart, gaps);
            copiedUpTo = index;
        }

        return output is null ? text : output.Append(text, copiedUpTo, text.Length - copiedUpTo).ToString();
    }

    public static string SubstituteLeetspeak(string text, char digitOneAs)
    {
        ArgumentNullException.ThrowIfNull(text);

        if (digitOneAs is not ('i' or 'l'))
        {
            throw new ArgumentOutOfRangeException(nameof(digitOneAs), digitOneAs, "The digit 1 is read as 'i' or 'l'.");
        }

        char[]? output = null;
        var index = 0;
        while (index < text.Length)
        {
            if (!IsWordCharacter(text[index]))
            {
                index++;
                continue;
            }

            var start = index;
            var hasLetter = false;
            var hasSubstitute = false;
            while (index < text.Length && IsWordCharacter(text[index]))
            {
                hasLetter |= char.IsLetter(text[index]);
                hasSubstitute |= LetterFor(text[index], digitOneAs) is not null;
                index++;
            }

            if (!hasLetter || !hasSubstitute)
            {
                continue;
            }

            for (var i = start; i < index; i++)
            {
                // A trailing '!' is punctuation ("stop!"), not a letter.
                if (text[i] == '!' && (i + 1 == index || text[i + 1] == '!'))
                {
                    continue;
                }

                if (LetterFor(text[i], digitOneAs) is { } letter)
                {
                    output ??= text.ToCharArray();
                    output[i] = letter;
                }
            }
        }

        return output is null ? text : new string(output);
    }

    private static char? LetterFor(char c, char digitOneAs) => c switch
    {
        '0' => 'o',
        '1' => digitOneAs,
        '3' => 'e',
        '4' => 'a',
        '5' => 's',
        '7' => 't',
        '9' => 'g',
        '@' => 'a',
        '$' => 's',
        '!' => 'i',
        _ => null,
    };

    private static bool IsCombiningMark(char c) =>
        CharUnicodeInfo.GetUnicodeCategory(c) is UnicodeCategory.NonSpacingMark or UnicodeCategory.EnclosingMark;

    // Letters, digits and the symbols that stand in for letters.
    private static bool IsWordCharacter(char c) => char.IsLetterOrDigit(c) || c is '@' or '$' or '!';

    private static bool IsSpacingSeparator(char c) =>
        c is ' ' or '\t' or '.' or '-' or '_' or '*' or '|' or '/' or '\\' or '+' or '~' or ',' or ':' or '·' or '•';

    // A word character standing alone: its neighbours are not word characters.
    private static bool IsSingleCharacterAt(string text, int index) =>
        IsWordCharacter(text[index])
        && (index == 0 || !IsWordCharacter(text[index - 1]))
        && (index + 1 == text.Length || !IsWordCharacter(text[index + 1]));

    private static bool TryFindNextSpacedCharacter(string text, int current, out Range gap, out int next)
    {
        var gapStart = current + 1;
        var gapEnd = gapStart;
        while (gapEnd < text.Length && gapEnd - gapStart < ObfuscationLimits.MaxSpacingGap && IsSpacingSeparator(text[gapEnd]))
        {
            gapEnd++;
        }

        gap = gapStart..gapEnd;
        next = gapEnd;
        return gapEnd > gapStart && gapEnd < text.Length && IsSingleCharacterAt(text, gapEnd);
    }

    private static void AppendCollapsedRun(StringBuilder output, string text, int runStart, List<Range> gaps)
    {
        var letterGap = MostCommonGap(text, gaps);
        var position = runStart;
        output.Append(text[position]);
        foreach (var gap in gaps)
        {
            if (!text.AsSpan(gap).SequenceEqual(letterGap))
            {
                output.Append(' ');
            }

            position = gap.End.Value;
            output.Append(text[position]);
        }
    }

    // Most frequent gap; ties go to the shorter, then the ordinally smaller gap, so the result is deterministic.
    private static ReadOnlySpan<char> MostCommonGap(string text, List<Range> gaps)
    {
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var gap in gaps)
        {
            var key = text[gap];
            counts[key] = counts.GetValueOrDefault(key) + 1;
        }

        return counts
            .OrderByDescending(entry => entry.Value)
            .ThenBy(entry => entry.Key.Length)
            .ThenBy(entry => entry.Key, StringComparer.Ordinal)
            .First()
            .Key;
    }
}
