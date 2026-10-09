using System.Text;

namespace AgentShield.Api.Http.Results;

/// <summary>Converts C# property paths (<c>Items[0].DisplayName</c>) to JSON paths (<c>items[0].displayName</c>).</summary>
internal static class PropertyPath
{
    public static string ToCamelCase(string? path)
    {
        if (string.IsNullOrEmpty(path))
        {
            return string.Empty;
        }

        var builder = new StringBuilder(path.Length);
        var startOfSegment = true;
        foreach (var character in path)
        {
            builder.Append(startOfSegment ? char.ToLowerInvariant(character) : character);
            startOfSegment = character is '.' or ']';
        }

        return builder.ToString();
    }
}
