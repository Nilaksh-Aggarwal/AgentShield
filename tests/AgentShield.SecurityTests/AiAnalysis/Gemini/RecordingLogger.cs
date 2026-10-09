using System.Collections.Concurrent;
using System.Globalization;
using Microsoft.Extensions.Logging;

namespace AgentShield.SecurityTests.AiAnalysis.Gemini;

/// <summary>Captures every log entry: level, event, rendered message, structured properties and exception.</summary>
internal sealed class RecordingLogger<T> : ILogger<T>
{
    public ConcurrentQueue<Entry> Entries { get; } = new();

    public IDisposable? BeginScope<TState>(TState state)
        where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
    {
        var properties = state is IEnumerable<KeyValuePair<string, object?>> pairs
            ? pairs.ToDictionary(pair => pair.Key, pair => Convert.ToString(pair.Value, CultureInfo.InvariantCulture), StringComparer.Ordinal)
            : [];
        Entries.Enqueue(new Entry(logLevel, eventId, formatter(state, exception), properties, exception));
    }

    /// <summary>Everything an entry would put in a log sink, as one string, for leak checks.</summary>
    public string AllText() => string.Concat(Entries.Select(entry =>
        entry.Message + string.Concat(entry.Properties.Values) + entry.Exception));

    internal sealed record Entry(
        LogLevel Level,
        EventId EventId,
        string Message,
        IReadOnlyDictionary<string, string?> Properties,
        Exception? Exception);
}
