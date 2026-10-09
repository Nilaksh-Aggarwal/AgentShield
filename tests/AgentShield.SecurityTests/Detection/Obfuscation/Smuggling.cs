using System.Text;

namespace AgentShield.SecurityTests.Detection.Obfuscation;

/// <summary>Builds text hidden in invisible characters, the way "ASCII smuggling" and "emoji smuggling" do.</summary>
internal static class Smuggling
{
    /// <summary>Each ASCII character as its invisible Unicode tag character (U+E0000 + code).</summary>
    public static string Tags(string ascii)
    {
        var builder = new StringBuilder(ascii.Length * 2);
        foreach (var c in ascii)
        {
            if (c is < ' ' or > '~')
            {
                throw new ArgumentException("Tag characters mirror printable ASCII only.", nameof(ascii));
            }

            builder.Append(char.ConvertFromUtf32(0xE0000 + c));
        }

        return builder.ToString();
    }

    /// <summary>Each UTF-8 byte of <paramref name="text"/> as a variation selector (bytes 0–15: U+FE00…, 16–255: U+E0100…).</summary>
    public static string Selectors(string text) => SelectorBytes(Encoding.UTF8.GetBytes(text));

    public static string SelectorBytes(params byte[] bytes)
    {
        var builder = new StringBuilder(bytes.Length * 2);
        foreach (var value in bytes)
        {
            builder.Append(value < 16 ? char.ConvertFromUtf32(0xFE00 + value) : char.ConvertFromUtf32(0xE0100 + value - 16));
        }

        return builder.ToString();
    }

    /// <summary>England's flag: a real emoji tag sequence (black flag, tags "gbeng", cancel tag).</summary>
    public const string EnglandFlag = "\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F";

    /// <summary>Scotland's flag (tags "gbsct").</summary>
    public const string ScotlandFlag = "\U0001F3F4\U000E0067\U000E0062\U000E0073\U000E0063\U000E0074\U000E007F";
}
