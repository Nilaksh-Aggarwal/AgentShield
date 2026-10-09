namespace AgentShield.Security.Detection.Obfuscation;

/// <summary>
/// Hard bounds on the work <see cref="ObfuscationDetector"/> does for one input, whatever the input contains.
/// </summary>
/// <remarks>
/// <para>Every transformation (decoder, unmasking or hidden-character step) is a single linear pass whose output is
/// never longer than its input, except the in-place reading of hidden characters, which is at most twice as long (two
/// separators per decoded run), so one view costs O(n). The number of views is fixed by the structure: 2 hidden-character
/// readings, 2 unmasking variants, up to 3 decoders at depth 1 and 3 × 3 at depth 2, 16 at most, all capped by
/// <see cref="MaxViews"/>. Each view is inspected by a fixed set of linear-time rules. Total work is therefore at most
/// <see cref="MaxViews"/> × <see cref="MaxViewLength"/> characters per rule.</para>
/// <para>Content that would exceed a limit is never silently skipped or truncated (an attacker would put the payload
/// just past the cut). The detector reports <see cref="ObfuscationDetector.UninspectableContentCode"/> instead, which
/// sends the input to review.</para>
/// </remarks>
internal static class ObfuscationLimits
{
    /// <summary>
    /// Layers of encoding that are undone: decode once and inspect, then decode that result once more and inspect.
    /// Two layers cover the common double-encoding tricks (<c>%2569</c>, Base64 of percent-encoded text) without
    /// letting nesting multiply the work. A third layer is not decoded.
    /// </summary>
    public const int MaxDecodingDepth = 2;

    /// <summary>Most transformed views inspected per input. The structure produces at most 16.</summary>
    public const int MaxViews = 16;

    /// <summary>
    /// Longest view (after normalisation) that is inspected: twice the API input limit of 32,000 characters. Decoding
    /// never lengthens text and the in-place hidden-character reading at most doubles it (64,000 at the API limit), so
    /// only Unicode compatibility expansion during normalisation (up to 18 characters for one, e.g. U+FDFA) can exceed
    /// it.
    /// </summary>
    public const int MaxViewLength = 65_536;

    /// <summary>
    /// Shortest run of Base64 characters that is decoded (12 bytes, e.g. a forged <c>&lt;|im_start|&gt;</c> token).
    /// Shorter runs are ordinary words and identifiers.
    /// </summary>
    public const int MinBase64Length = 16;

    /// <summary>Fewest single characters separated by gaps that count as spaced-out text (<c>i g n o r e</c>).</summary>
    public const int MinSpacedCharacters = 4;

    /// <summary>Longest gap between spaced-out characters (<c>i / g / n</c>). A longer gap ends the run.</summary>
    public const int MaxSpacingGap = 3;

    /// <summary>
    /// Shortest run of consecutive variation selectors that is read as hidden bytes. Legitimate text uses one selector
    /// after a character (emoji presentation, ideographic variants) and never two in a row.
    /// </summary>
    public const int MinVariationSelectorRun = 2;
}
