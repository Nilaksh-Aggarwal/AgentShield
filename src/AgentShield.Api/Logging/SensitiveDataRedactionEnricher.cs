using AgentShield.Security.Redaction;
using Serilog.Core;
using Serilog.Events;

namespace AgentShield.Api.Logging;

/// <summary>
/// Serilog adapter for <see cref="SensitiveDataRedactor"/>: masks properties whose name denotes a secret
/// (at any depth) and secret-looking substrings inside string values. Registered as the last enricher so
/// it sees every property.
/// </summary>
/// <remarks>
/// Exception text is not rewritten — exception messages must not contain secrets in the first place.
/// </remarks>
internal sealed class SensitiveDataRedactionEnricher : ILogEventEnricher
{
    private static readonly ScalarValue MaskValue = new(SensitiveDataRedactor.Mask);

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        ArgumentNullException.ThrowIfNull(logEvent);

        List<LogEventProperty>? replacements = null;
        foreach (var (name, value) in logEvent.Properties)
        {
            var redacted = SensitiveDataRedactor.IsSensitiveKey(name) ? MaskValue : Redact(value);
            if (!ReferenceEquals(redacted, value))
            {
                (replacements ??= []).Add(new LogEventProperty(name, redacted));
            }
        }

        if (replacements is null)
        {
            return;
        }

        foreach (var property in replacements)
        {
            logEvent.AddOrUpdateProperty(property);
        }
    }

    // Returns the same instance when nothing changed, so untouched events are not reallocated.
    private static LogEventPropertyValue Redact(LogEventPropertyValue value)
    {
        switch (value)
        {
            case ScalarValue { Value: string text }:
            {
                var redacted = SensitiveDataRedactor.RedactValue(text);
                return string.Equals(redacted, text, StringComparison.Ordinal) ? value : new ScalarValue(redacted);
            }

            case StructureValue structure:
            {
                var changed = false;
                var properties = structure.Properties.Select(property =>
                {
                    var redacted = SensitiveDataRedactor.IsSensitiveKey(property.Name) ? MaskValue : Redact(property.Value);
                    changed |= !ReferenceEquals(redacted, property.Value);
                    return new LogEventProperty(property.Name, redacted);
                }).ToList();
                return changed ? new StructureValue(properties, structure.TypeTag) : value;
            }

            case SequenceValue sequence:
            {
                var elements = sequence.Elements.Select(Redact).ToList();
                return elements.Where((element, index) => !ReferenceEquals(element, sequence.Elements[index])).Any()
                    ? new SequenceValue(elements)
                    : value;
            }

            case DictionaryValue dictionary:
            {
                var changed = false;
                var entries = dictionary.Elements.Select(entry =>
                {
                    var redacted = entry.Key.Value is string key && SensitiveDataRedactor.IsSensitiveKey(key)
                        ? MaskValue
                        : Redact(entry.Value);
                    changed |= !ReferenceEquals(redacted, entry.Value);
                    return new KeyValuePair<ScalarValue, LogEventPropertyValue>(entry.Key, redacted);
                }).ToList();
                return changed ? new DictionaryValue(entries) : value;
            }

            default:
                return value;
        }
    }
}
