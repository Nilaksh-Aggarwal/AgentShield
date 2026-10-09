namespace AgentShield.Domain.Agents.Tools;

/// <summary>
/// The arguments of <c>knowledge.lookup</c>, the reference tool behind the tool gateway: one search text.
/// </summary>
/// <remarks>
/// <para>The schema, enforced here so that no instance can violate it: <see cref="Query"/> is 1–<see cref="MaxQueryLength"/>
/// characters, not only whitespace, without control characters (line breaks included), and well-formed UTF-16. The value is
/// kept exactly as sent (no trimming or folding): the tool decides how to match it.</para>
/// <para>The query is untrusted content. It is never logged or recorded, and the tool's answer never repeats it.</para>
/// </remarks>
public sealed record KnowledgeLookupArguments : ToolArguments
{
    public const int MaxQueryLength = 200;

    public KnowledgeLookupArguments(string query)
    {
        // The messages never quote the value.
        ArgumentNullException.ThrowIfNull(query);
        Query = Validate(query) is { } violation
            ? throw new ArgumentException($"Not a valid knowledge lookup query ({violation}).", nameof(query))
            : query;
    }

    public string Query { get; }

    /// <summary>The arguments without the query, which is untrusted content (a record would print it).</summary>
    public override string ToString() => $"KnowledgeLookupArguments {{ Query = ({Query.Length} characters) }}";

    /// <summary>The first rule <paramref name="query"/> breaks, or <see langword="null"/> when it is a valid query.</summary>
    public static ToolArgumentViolation? Validate(string query)
    {
        ArgumentNullException.ThrowIfNull(query);

        if (string.IsNullOrWhiteSpace(query))
        {
            return ToolArgumentViolation.Empty;
        }

        if (query.Length > MaxQueryLength)
        {
            return ToolArgumentViolation.TooLong;
        }

        for (var index = 0; index < query.Length; index++)
        {
            var character = query[index];
            if (char.IsControl(character))
            {
                return ToolArgumentViolation.InvalidText;
            }

            if (char.IsHighSurrogate(character) && index + 1 < query.Length && char.IsLowSurrogate(query[index + 1]))
            {
                index++;
            }
            else if (char.IsSurrogate(character))
            {
                return ToolArgumentViolation.InvalidText;
            }
        }

        return null;
    }
}
