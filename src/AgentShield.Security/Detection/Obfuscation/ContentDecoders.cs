using System.Buffers;
using System.Net;
using System.Text;
using System.Text.Unicode;

namespace AgentShield.Security.Detection.Obfuscation;

/// <summary>
/// Bounded, single-pass decoders for encodings used to smuggle instructions past keyword filters. Each returns the
/// whole text with the encoded parts decoded in place, or <see langword="null"/> when there was nothing to decode.
/// </summary>
/// <remarks>
/// Decoding is only a way to look at the content: a decoder never raises a finding, and content that merely looks
/// encoded (hashes, identifiers, JWTs, images) is either left alone or decodes to text that matches no rule. Every
/// decoder is linear in the input, never recursive, and its output is never longer than its input.
/// </remarks>
internal static class ContentDecoders
{
    /// <summary>
    /// Decodes runs of at least <see cref="ObfuscationLimits.MinBase64Length"/> Base64 characters (standard or URL-safe
    /// alphabet, optional padding) that decode to well-formed UTF-8 text. Runs that decode to binary data, invalid
    /// UTF-8 or text with control characters are left unchanged.
    /// </summary>
    public static string? DecodeBase64Segments(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        StringBuilder? output = null;
        var copiedUpTo = 0;
        var index = 0;
        while (index < text.Length)
        {
            if (!IsBase64Character(text[index]))
            {
                index++;
                continue;
            }

            var start = index;
            while (index < text.Length && IsBase64Character(text[index]))
            {
                index++;
            }

            var dataLength = index - start;
            var padding = 0;
            while (index < text.Length && text[index] == '=' && padding < 2)
            {
                index++;
                padding++;
            }

            var decoded = TryDecodeBase64Text(text.AsSpan(start, dataLength), padding);
            if (decoded is null)
            {
                continue;
            }

            output ??= new StringBuilder(text.Length);
            output.Append(text, copiedUpTo, start - copiedUpTo).Append(decoded);
            copiedUpTo = index;
        }

        return output?.Append(text, copiedUpTo, text.Length - copiedUpTo).ToString();
    }

    /// <summary>
    /// Decodes percent escapes (<c>%69gnore</c>) as UTF-8. Invalid sequences stay as they are; <c>+</c> is not turned
    /// into a space (detection rules already treat it as a word separator).
    /// </summary>
    public static string? DecodePercentEncoding(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        if (!ContainsPercentEscape(text))
        {
            return null;
        }

        var decoded = Uri.UnescapeDataString(text);
        return string.Equals(decoded, text, StringComparison.Ordinal) ? null : decoded;
    }

    /// <summary>
    /// Decodes HTML character references: named (<c>&amp;lt;</c>), decimal (<c>&amp;#105;</c>) and hexadecimal
    /// (<c>&amp;#x69;</c>).
    /// </summary>
    public static string? DecodeHtmlEntities(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        if (!text.Contains('&', StringComparison.Ordinal))
        {
            return null;
        }

        var decoded = WebUtility.HtmlDecode(text);
        return string.Equals(decoded, text, StringComparison.Ordinal) ? null : decoded;
    }

    private static string? TryDecodeBase64Text(ReadOnlySpan<char> data, int padding)
    {
        if (data.Length < ObfuscationLimits.MinBase64Length || data.Length % 4 == 1)
        {
            return null;
        }

        // A run mixing both alphabets is not Base64 (e.g. a path such as a/b-c).
        if (data.ContainsAny('+', '/') && data.ContainsAny('-', '_'))
        {
            return null;
        }

        var paddedLength = (data.Length + 3) / 4 * 4;
        if (padding > 0 && data.Length + padding != paddedLength)
        {
            return null;
        }

        var chars = ArrayPool<char>.Shared.Rent(paddedLength);
        var bytes = ArrayPool<byte>.Shared.Rent(paddedLength / 4 * 3);
        try
        {
            for (var i = 0; i < data.Length; i++)
            {
                chars[i] = data[i] switch
                {
                    '-' => '+',
                    '_' => '/',
                    var c => c,
                };
            }

            chars.AsSpan(data.Length, paddedLength - data.Length).Fill('=');

            if (!Convert.TryFromBase64Chars(chars.AsSpan(0, paddedLength), bytes, out var written)
                || !Utf8.IsValid(bytes.AsSpan(0, written)))
            {
                return null;
            }

            var decoded = Encoding.UTF8.GetString(bytes, 0, written);
            return IsPlausibleText(decoded) ? decoded : null;
        }
        finally
        {
            ArrayPool<char>.Shared.Return(chars);
            ArrayPool<byte>.Shared.Return(bytes);
        }
    }

    // Binary data decodes to control characters almost immediately; text does not contain them (tabs and line breaks
    // aside).
    private static bool IsPlausibleText(string decoded)
    {
        foreach (var c in decoded)
        {
            if (char.IsControl(c) && c is not ('\t' or '\n' or '\r'))
            {
                return false;
            }
        }

        return decoded.Length > 0;
    }

    private static bool IsBase64Character(char c) =>
        char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '-' or '_';

    private static bool ContainsPercentEscape(string text)
    {
        var index = text.IndexOf('%', StringComparison.Ordinal);
        while (index >= 0 && index + 2 < text.Length)
        {
            if (char.IsAsciiHexDigit(text[index + 1]) && char.IsAsciiHexDigit(text[index + 2]))
            {
                return true;
            }

            index = text.IndexOf('%', index + 1);
        }

        return false;
    }
}
