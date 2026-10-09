# 0009 — Strict JSON input

- **Status:** Accepted — 2026-09-29

## Context

Every request body is untrusted, and the firewall's job is to judge exactly what the client sent. If a JSON text
admits more than one reading, another component can read it differently from us: an upstream gateway or WAF, a log
pipeline, the agent framework that sends the request. That mismatch lets a payload through (a parser differential,
the same idea as request smuggling). The previous configuration accepted several such inputs silently. Every example
below was verified on .NET 10 before this change:

| Input | Previous behaviour |
|---|---|
| `{"input":"hello","input":"malicious"}` | last value won (`"malicious"`) |
| `{"input":"hello","INPUT":"x"}` / `{"Input":"x"}` | case-insensitive match, last value won |
| `{"input":"hello","isAdmin":true}` | unknown property silently ignored |
| `"decision": 999` / `"decision": "1"` | accepted as an (undefined / numeric) enum value |
| `"decision": "Block, Sanitize"` | accepted and OR-ed: **`Review`** (1 \| 2 = 3) |
| `"decision": " block"` | accepted as `Block` |
| 400 response bodies | System.Text.Json messages naming CLR types (`AgentShield…ProbeEchoRequest`, `System.String`) |

## Decision

All request bodies are read strictly. The policy is global, not per endpoint, because every body is untrusted. The
settings are read-side only, so response serialisation is unaffected. It is configured once in `JsonConventions`
for both the MVC and HTTP (minimal API / Problem Details) option sets:

| Setting | Value | Effect |
|---|---|---|
| `AllowDuplicateProperties` | `false` | Duplicate names → 400, at any depth, including dictionaries and `JsonElement` |
| `UnmappedMemberHandling` | `Disallow` | Unknown properties → 400 |
| `PropertyNameCaseInsensitive` | `false` | `"Input"` is an unknown property, not an alias of `"input"` |
| Enum converter | `StrictStringEnumConverterFactory` | Only exact declared names (or `[JsonStringEnumMemberName]`); no integers, numeric strings, other casing, whitespace or lists. `[Flags]` enums fall back to `JsonStringEnumConverter(allowIntegerValues: false)` |
| `NumberHandling` | `Strict` | `"42"` is not a number (unchanged) |
| Comments / trailing commas | disallowed | (unchanged) |
| `MaxDepth` | 32 | Deeper payloads → 400. Request DTOs are far shallower |
| MVC `AllowInputFormatterExceptionMessages` | `false` | 400 bodies carry the JSON path (`errors["$.input"]`) and a generic message, never CLR type names or parser positions |
| Request body size | `Api:MaxRequestBodySizeBytes` (1 MiB) | 413 via Kestrel (unchanged; now tested on real Kestrel) |

Also rejected with 400, as System.Text.Json behaviour we rely on: malformed JSON, multiple top-level values, invalid
UTF-8, unpaired surrogate escapes (`"\ud800"`), wrong JSON types, and `null` for a non-nullable value type.

**Deliberately not enabled:** `RespectNullableAnnotations` and `RespectRequiredConstructorParameters` (both part of
the .NET `JsonSerializerOptions.Strict` preset). With them, an explicit `null` would be a 400 while a missing property
stayed a 422, and every missing positional-record property would become a 400, so the same "no value" condition
would get two answers. Instead, request DTOs declare client-optional members as nullable (`string?`, `int?`) and
the validator decides presence and emptiness (422). `[JsonRequired]` and C# `required` are not used on request DTOs
for the same reason.

## Consequences

- Clients must send exactly the documented contract: camelCase names, no extra fields, enum names as documented. The
  frontend already does.
- Endpoint-specific limits belong to the endpoint, not the parser: e.g. the firewall request's maximum input length
  is a validator rule (422, `Firewall.InputTooLarge`), and an endpoint may apply a stricter `[RequestSizeLimit]`.
- Adding a member to a request DTO is backwards compatible; removing one breaks clients that still send it (400).
- Covered by `JsonInputPolicyTests`, `RequestSizeLimitTests` and `SwaggerTests.OpenApiDocument_DescribesEnumsAsTheirDeclaredNames`
  (ApiTests). With the previous configuration restored, 23 of the 40 `JsonInputPolicyTests` cases fail.
