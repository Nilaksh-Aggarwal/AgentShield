# 0013 — First AI provider: Google Gemini through the official Google Gen AI SDK

- **Status:** Accepted — 2026-09-29. HTTP 401/403/404 map to `RequestRejected` instead of `Unavailable` since Milestone 6
  step 3 ([0016](0016-ai-provider-circuit-breaker-and-input-token-budget.md)): a configuration fault is not an outage.
- **Extends:** [0012](0012-ai-analysis-boundary.md) (AI analysis boundary). Nothing is superseded: the provider is one
  `IAiSecurityAnalyzer` adapter behind the existing guard.

## Context

Milestone 3 built the AI analysis boundary with a scripted test double and no real provider. The project uses the
Gemini API free tier. The provider must plug into the existing contracts without weakening any control: the
disclosure policy, the strict parser, central validation, the 3 s guard, the failure table and the rule that the LLM
never decides. Configuration must allow AI to be off (the Milestone 2 behaviour) with no key and no startup dependency
on Google.

## Decision

- **SDK: `Google.GenAI` 1.22.0**, the official Google Gen AI SDK for .NET (github.com/googleapis/dotnet-genai), not the
  deprecated `Google.Ai.Generativelanguage` or community `GoogleGenerativeAI` packages, and no LangChain/Semantic Kernel.
  It speaks the Gemini API's `generateContent` with `responseMimeType` + `responseJsonSchema` and exposes
  `ClientOptions.HttpClientFactory`, so HTTP still goes through `IHttpClientFactory` (CLAUDE.md §8). Plus
  `Microsoft.Extensions.Http` 10.0.12 for `AddHttpClient`.
- **One adapter, `GeminiSecurityAnalyzer` (AI project, internal).** A typed `HttpClient` client (transient; the scoped AI
  stage resolves one per request). It owns one SDK `Client` and disposes it, together with the `HttpClient` (the SDK
  disposes the `HttpClient` it received). It returns the raw answer through the shared `AiStructuredOutputParser` or an
  `AiAnalysisErrors` failure; it builds no findings and makes no decision.
- **Configuration `Ai` (`AiOptions` + nested `GeminiOptions`, validated at startup):** `Enabled` (`false` in
  both appsettings files), `Provider`
  (`Gemini`, the only value), `Model` (default `gemini-3.8-flash`; lower-case letters, digits, `.`, `-`, because it
  becomes part of the URL), `TimeoutSeconds` (1–3, default 3; the provider's own timeout, never above the stage's 3 s).
  The provider is registered only when `Enabled` is true, so a disabled app needs no key and never calls Google.
- **API key `Ai:Gemini:ApiKey`** from ASP.NET Core User Secrets (Development) or `Ai__Gemini__ApiKey` (environment).
  Committed appsettings hold only an empty placeholder, which later sources override. Required when enabled with
  Gemini (startup fails otherwise). Sent only in the `x-goog-api-key` header; never logged, returned or in Swagger.
- **Hardening beyond SDK defaults (each verified against the SDK and tested):** base URL pinned (the SDK would take
  `GOOGLE_GEMINI_BASE_URL` from the environment and send the key there); `enterprise`/`vertexAI` explicitly `false`;
  retries pinned to one attempt; the typed client's `Timeout` is the provider timeout (the SDK ignores its own timeout
  option for an injected client); the response is capped at 256 KiB (`MaxResponseContentBufferSize`); only the first
  candidate's non-thought text is read (the SDK's `Text` includes thoughts); provider exception messages (which carry
  the provider's error body) are never used.
- **Request:** a fixed system instruction and one user turn that is a JSON document
  `{ "deterministicFindings": [...], "content": "..." }`, so the untrusted content is a JSON string value and cannot close
  a delimiter. Structured output via `responseJsonSchema` (catalogue enums, `additionalProperties: false`,
  `maxItems: 16`, confidence 0–1, explicit `propertyOrdering`). Text only: no tools, grounding, code execution or media.
  Temperature at the model default (Google's guidance for Gemini 3); low thinking for latency (the lowest level `gemini-3.8-flash` accepts; `MINIMAL` is rejected with HTTP 400); `maxOutputTokens`
  4096; one candidate. Structured output is not trusted: the strict parser and central validator still run.
- **HTTP status by cause** (the failure table of ADR 0012 applied to Gemini): 429 → `RateLimited`; 5xx (except 504) and
  401/403/404 (key, permission, model: configuration the input cannot cause) → `Unavailable`; 408/504 → `Timeout`;
  400, 413 and every other status → new `AiAnalysisErrors.RequestRejected` (the request carried the content, so it may
  be content-induced), which the stage maps explicitly to `UnclassifiedFailure` (Review). Network errors →
  `NetworkFailure`; an oversized response, a non-JSON envelope, a truncated (`MAX_TOKENS`) or otherwise incomplete answer
  → `MalformedResponse`; a blocked prompt or safety-type finish reason → `Refused`.
- **Logging:** the adapter logs one Warning per failure (EventId 1100) with `FailureCategory`, `HttpStatus`,
  `FinishReason` (known SDK values only), `AiModel`, `DurationMs`. Nothing on success (the security event covers it).
- **Tests never call Google.** The adapter is tested through the real SDK against a fake HTTP handler; the composition
  is tested with the fake as the primary handler of every `IHttpClientFactory` client. A manual smoke test runs against
  the real API only through the manual script `scripts/gemini-smoke.ps1` (not part of the test suite). Test factories force AI off and a blank
  key, so Development settings and User Secrets never reach a test host.

## Consequences

- AI off (default): identical to Milestone 2/3 behaviour, no key, no outbound call. AI on: Gemini findings join the
  deterministic ones through the unchanged aggregator, risk engine and policy engine.
- Replacing or adding a provider means another adapter plus an `Ai:Provider` value; Application, Security and
  Api do not change. Multi-provider fallback and circuit breaking are deliberately not built.
- An invalid key produces HTTP 400 on the Gemini API, which is classified as `RequestRejected` → Review for every input
  (fail safe, visible as EventId 1100 with `HttpStatus` 400). Startup does not call Google to check the key.
- New transitive packages: `Google.Apis`, `Google.Apis.Auth`, `Google.Apis.Core` 1.69.0 (the SDK's auth layer, used for
  Vertex AI), `Newtonsoft.Json` 13.0.3, `System.Management` 7.0.2, `MimeTypes` 2.5.2, `Microsoft.Extensions.AI.Abstractions`
  10.6.0. No known vulnerabilities at adoption.
- The free tier has per-minute and per-day quotas; exceeding them is `RateLimited` (deterministic decision stands).
- **Free-tier data use:** under the Gemini API terms for Unpaid Services, Google uses submitted content and responses to
  provide, improve and develop its products, human reviewers may read them, and Google asks users not to submit
  sensitive, confidential or personal information. The disclosure policy masks common secret formats but does no PII
  handling. AI analysis therefore stays **off by default** and is for demo and test content only on the free tier; real
  user data needs the paid tier (or another provider) and a disclosure-policy review first.
- Full specification: [docs/security/ai-analysis.md](../security/ai-analysis.md), section "Gemini provider".

## Amendment — 2026-09-29: configuration section `Ai`, key in User Secrets

The first version read the key only from a `GEMINI_API_KEY` configuration key and kept it out of the options section
(internal property) so that no appsettings file could supply it. On request, the configuration was restructured to the
conventional ASP.NET Core layout: section `Ai` (was `AiAnalysis`), options class `AiOptions` (was `AiAnalysisOptions`)
with a nested `Gemini.ApiKey`, the secret stored with User Secrets (`UserSecretsId` added to `AgentShield.Api.csproj`)
under `Ai:Gemini:ApiKey`, and `GEMINI_API_KEY` no longer read (one key source). The protection against a committed key
moved from "the binder cannot read it" to: an empty placeholder in both appsettings files (pinned by a test), User
Secrets/environment variables overriding it by the default configuration order, `GeminiOptions.ToString()` that never
prints the key, and test factories that blank it. AI stays off in both appsettings files; a developer enables it explicitly (`Ai:Enabled` in User Secrets or
`Ai__Enabled=true`) together with the key.

## Amendment — 2026-10-01: no redirects, no provider text in exceptions

Two additions to the hardening list, found in the security review (H-01, H-03 in `docs/security/defect-matrix.md`):

- **Redirects are not followed.** The typed client's primary handler is configured with `AllowAutoRedirect = false`
  (configured, not replaced, so test transports stay in place). .NET sends custom headers such as `x-goog-api-key` again
  on a redirect, so following one would have sent the key and the content to whatever host the response named; pinning
  the base URL covers the first request only. A 3xx reaches the SDK as the response itself and is classified by its
  status (`RequestRejected`, Review, not counted by the circuit breaker).
- **Exceptions the adapter does not map leave it without their message.** They become `GeminiAdapterFaultException`
  (type names of the exception and its inner exceptions, original stack trace), because .NET quotes offending values in
  messages such as `FormatException`'s and the global exception handler logs what reaches it. The analysis still fails
  closed (500).
