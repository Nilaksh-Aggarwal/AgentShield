using System.Collections.ObjectModel;

namespace AgentShield.Application.Common.Results;

/// <summary>
/// An expected application failure.
/// </summary>
/// <remarks>
/// <para><see cref="Code"/> is a stable, machine-readable identifier (e.g. <c>Firewall.InputTooLarge</c>) that
/// clients may branch on. <see cref="Message"/> is safe to show to API consumers — it must never contain
/// secrets, stack traces, connection strings or raw exception text.</para>
/// <para>Contains no HTTP concepts; see the API layer for the mapping to status codes.</para>
/// </remarks>
public sealed record Error
{
    /// <summary>Metadata key under which a validation error records the offending property.</summary>
    public const string PropertyNameKey = "propertyName";

    private static readonly IReadOnlyDictionary<string, object?> EmptyMetadata =
        ReadOnlyDictionary<string, object?>.Empty;

    public Error(string code, string message, ErrorType type, IReadOnlyDictionary<string, object?>? metadata = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(code);
        ArgumentException.ThrowIfNullOrWhiteSpace(message);

        Code = code;
        Message = message;
        Type = type;
        Metadata = metadata is null || metadata.Count == 0
            ? EmptyMetadata
            : new ReadOnlyDictionary<string, object?>(new Dictionary<string, object?>(metadata, StringComparer.Ordinal));
    }

    public string Code { get; }

    public string Message { get; }

    public ErrorType Type { get; }

    public IReadOnlyDictionary<string, object?> Metadata { get; }

    /// <summary>The property a validation error refers to, if any.</summary>
    public string? PropertyName =>
        Metadata.TryGetValue(PropertyNameKey, out var value) ? value as string : null;

    public static Error Validation(string propertyName, string message, string code = "Validation.Invalid") =>
        new(code, message, ErrorType.Validation, new Dictionary<string, object?> { [PropertyNameKey] = propertyName });

    public static Error NotFound(string code, string message) => new(code, message, ErrorType.NotFound);

    public static Error Conflict(string code, string message) => new(code, message, ErrorType.Conflict);

    public static Error Unauthorized(string code, string message) => new(code, message, ErrorType.Unauthorized);

    public static Error Forbidden(string code, string message) => new(code, message, ErrorType.Forbidden);

    public static Error BusinessRule(string code, string message) => new(code, message, ErrorType.BusinessRule);

    public static Error ExternalDependency(string code, string message) =>
        new(code, message, ErrorType.ExternalDependency);

    public static Error Unexpected(string code, string message) => new(code, message, ErrorType.Unexpected);

    /// <summary>Returns a copy of this error with an additional metadata entry.</summary>
    public Error WithMetadata(string key, object? value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);

        var metadata = new Dictionary<string, object?>(Metadata, StringComparer.Ordinal) { [key] = value };
        return new Error(Code, Message, Type, metadata);
    }

    // Records compare dictionaries by reference; compare metadata by content instead.
    public bool Equals(Error? other) =>
        other is not null
        && Code == other.Code
        && Message == other.Message
        && Type == other.Type
        && Metadata.Count == other.Metadata.Count
        && Metadata.All(pair => other.Metadata.TryGetValue(pair.Key, out var value) && Equals(pair.Value, value));

    public override int GetHashCode() => HashCode.Combine(Code, Message, Type);
}
