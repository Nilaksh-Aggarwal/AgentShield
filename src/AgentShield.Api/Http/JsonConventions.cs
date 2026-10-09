using System.Text.Json;
using System.Text.Json.Serialization;

namespace AgentShield.Api.Http;

/// <summary>
/// The one JSON configuration for the API, applied to both MVC and the minimal/HTTP pipeline
/// (Problem Details writer, health checks). Controllers must not configure serialisation locally.
/// </summary>
/// <remarks>
/// Every request body is untrusted, so reading is strict: one JSON text has exactly one interpretation, and
/// anything ambiguous is rejected (400) instead of being resolved silently. The read-side settings below do
/// not affect how responses are written. Rationale and trade-offs: docs/decisions/0009-strict-json-input.md.
/// </remarks>
internal static class JsonConventions
{
    /// <summary>Nesting limit for request and response JSON; request DTOs are far shallower.</summary>
    public const int MaxDepth = 32;

    public static void Apply(JsonSerializerOptions options)
    {
        options.PropertyNamingPolicy = JsonNamingPolicy.CamelCase;

        // {"input":"a","input":"b"} is rejected rather than "last value wins" (also inside nested objects,
        // dictionaries and JsonElement values).
        options.AllowDuplicateProperties = false;

        // Unknown properties are rejected rather than ignored, and names match exactly: "Input" or "INPUT" is an
        // unknown property, not a second spelling of "input".
        options.UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow;
        options.PropertyNameCaseInsensitive = false;

        // Enums travel as their exact declared names: no integers, numeric strings, other casings or lists.
        options.Converters.Add(new StrictStringEnumConverterFactory());
        // [Flags] enums (none yet) fall back to the built-in converter, still without integer values.
        options.Converters.Add(new JsonStringEnumConverter(namingPolicy: null, allowIntegerValues: false));

        // Web defaults accept numbers inside strings ("42"); a security API should not be lenient.
        options.NumberHandling = JsonNumberHandling.Strict;
        options.ReadCommentHandling = JsonCommentHandling.Disallow;
        options.AllowTrailingCommas = false;
        options.MaxDepth = MaxDepth;

        // Deliberately left at their default (false): a missing or null property binds as null/default and the
        // request's validator reports it (422). RespectNullableAnnotations would turn an explicit null into a
        // 400 while a missing property stayed a 422, and RespectRequiredConstructorParameters would turn every
        // missing positional-record property into a 400 — two answers for the same "no value" condition.
        options.RespectNullableAnnotations = false;
        options.RespectRequiredConstructorParameters = false;
    }
}
