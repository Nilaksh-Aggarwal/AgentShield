namespace AgentShield.Domain.Agents.Tools;

/// <summary>
/// What a tool returned through the gateway: whether it found or produced something, and a bounded text.
/// </summary>
/// <remarks>
/// A closed, bounded shape, so the gateway's response never carries more than this, whatever a tool does. The reference tool
/// returns text from its own fixed dataset only, never the caller's query.
/// </remarks>
public sealed record ToolOutput
{
    public const int MaxTextLength = 2_000;

    public ToolOutput(bool found, string? text)
    {
        if (!found && text is not null)
        {
            throw new ArgumentException("An output that found nothing carries no text.", nameof(text));
        }

        if (text is { Length: 0 or > MaxTextLength })
        {
            throw new ArgumentOutOfRangeException(nameof(text), text.Length, $"A tool's text must be 1-{MaxTextLength} characters.");
        }

        Found = found;
        Text = text;
    }

    /// <summary>Whether the tool found (or produced) a result.</summary>
    public bool Found { get; }

    /// <summary>The result text; <see langword="null"/> when nothing was found.</summary>
    public string? Text { get; }

    /// <summary>Nothing found.</summary>
    public static ToolOutput NotFound { get; } = new(found: false, text: null);
}
