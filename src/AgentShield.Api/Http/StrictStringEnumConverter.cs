using System.Collections.Frozen;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AgentShield.Api.Http;

/// <summary>
/// Reads and writes enums as their declared names only, compared exactly (ordinal, case-sensitive).
/// </summary>
/// <remarks>
/// The built-in <see cref="JsonStringEnumConverter"/> is lenient even with integers disabled: it accepts any
/// casing (<c>"block"</c>), surrounding whitespace (<c>" Block"</c>) and comma-separated lists that are OR-ed
/// together even for non-flags enums — <c>"Block, Sanitize"</c> silently becomes <c>Review</c> when
/// Block = 1, Sanitize = 2, Review = 3. For untrusted input every value must have exactly one spelling, so this
/// converter accepts nothing but a JSON string equal to a declared name (or its
/// <see cref="JsonStringEnumMemberNameAttribute"/> name). <c>[Flags]</c> enums are left to the built-in converter.
/// </remarks>
internal sealed class StrictStringEnumConverterFactory : JsonConverterFactory
{
    public override bool CanConvert(Type typeToConvert) =>
        typeToConvert.IsEnum && !typeToConvert.IsDefined(typeof(FlagsAttribute), inherit: false);

    public override JsonConverter CreateConverter(Type typeToConvert, JsonSerializerOptions options) =>
        (JsonConverter)Activator.CreateInstance(typeof(StrictStringEnumConverter<>).MakeGenericType(typeToConvert))!;
}

internal sealed class StrictStringEnumConverter<TEnum> : JsonConverter<TEnum>
    where TEnum : struct, Enum
{
    private static readonly (string Name, TEnum Value)[] Members = typeof(TEnum)
        .GetFields(BindingFlags.Public | BindingFlags.Static)
        .Select(field => (field.GetCustomAttribute<JsonStringEnumMemberNameAttribute>()?.Name ?? field.Name, (TEnum)field.GetValue(null)!))
        .ToArray();

    private static readonly FrozenDictionary<string, TEnum> ValuesByName =
        Members.ToFrozenDictionary(member => member.Name, member => member.Value, StringComparer.Ordinal);

    // For aliases (two names, one value) the first declared name is written.
    private static readonly FrozenDictionary<TEnum, string> NamesByValue =
        Members.DistinctBy(member => member.Value).ToFrozenDictionary(member => member.Value, member => member.Name);

    public override TEnum Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        reader.TokenType == JsonTokenType.String ? Parse(reader.GetString()) : throw new JsonException();

    public override void Write(Utf8JsonWriter writer, TEnum value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WriteStringValue(NameOf(value));
    }

    public override TEnum ReadAsPropertyName(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options) =>
        Parse(reader.GetString());

    public override void WriteAsPropertyName(Utf8JsonWriter writer, TEnum value, JsonSerializerOptions options)
    {
        ArgumentNullException.ThrowIfNull(writer);
        writer.WritePropertyName(NameOf(value));
    }

    // A JsonException without a message makes the serializer report the standard "could not be converted" error with the path.
    private static TEnum Parse(string? name) =>
        name is not null && ValuesByName.TryGetValue(name, out var value) ? value : throw new JsonException();

    // An undefined value is a server-side bug; writing it as a number would break the "enums as names" contract.
    private static string NameOf(TEnum value) =>
        NamesByValue.TryGetValue(value, out var name)
            ? name
            : throw new JsonException($"Cannot serialise an undefined {typeof(TEnum).Name} value.");
}
