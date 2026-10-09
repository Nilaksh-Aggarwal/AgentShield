# Security principles

## 1. Deterministic control over security decisions

The LLM is an **analysis component**, never the final authority. The pipeline is:

```text
Input → Normalisation → Deterministic detection → AI-assisted analysis (optional) → Risk evaluation
      → Deterministic policy → Decision → Authorization → Audit
```

- "Authorization" in this pipeline is the authorization of an agent's *action*. Since Milestone 10 it exists as a
  separate decision, `POST /api/v1/agent/actions/authorize`: configured agents bound to their runtime, one required
  capability per tool action, risk from declared effects, a deterministic ordered policy, and the input decision can only
  tighten ([agent-action-authorization.md](agent-action-authorization.md), ADR 0020). It decides; it does not execute.
  Since Milestone 11 the tool gateway enforces it for the tools behind it (one reference tool): the agent is its
  credential, arguments are checked, and a signed, single-use grant is needed to run the tool
  ([tool-gateway.md](tool-gateway.md), ADR 0021). The API *caller* is authenticated, authorized and rate limited
  earlier, at the HTTP boundary, before any input is read (API key → permission policy → rate limit;
  [ADR 0014](../decisions/0014-api-boundary-hardening.md)).
- The agent proposes; the boundary decides; the gateway holds the tool. An agent cannot grant itself a capability, name a
  decision, or lower one, and it never holds anything that executes a tool; the LLM is not consulted for agent actions at
  all.
- Normalisation (Unicode, encodings, obfuscation) happens before any detection.
- Deterministic detectors run first and cannot be overridden by AI output.
- AI output is treated as untrusted data: it contributes findings from a closed catalogue, validated all or nothing,
  that enter the same fusion, risk and policy as detector findings. It cannot produce a decision, and it cannot
  lower, rewrite or remove a deterministic finding. Every failure of an expected AI analysis, provider outages
  included, holds the input for review; nothing falls back to the deterministic decision alone
  ([ai-analysis.md](ai-analysis.md), ADRs 0012 and 0016).
- The policy engine (Security, deterministic, testable) maps risk to a decision. Implemented today: ALLOW / REVIEW /
  BLOCK (SANITIZE needs a rewriting stage and comes later).
- Decisions are auditable: every decision is recorded as a security event with its own `SecurityEventId` and the
  request `CorrelationId` (structured log today; persistence later).
- Stages fail closed: a detector or audit failure fails the request (500) rather than returning an unaudited or
  partially analysed decision (ADR 0010).

The implemented pipeline, detector rules, risk scoring and policy are specified in
[firewall-pipeline.md](firewall-pipeline.md).

## 2. Threats in scope

Detected today (deterministic, English keyword rules): instruction override, role manipulation (forged chat-template
delimiters, unrestricted personas, authority claims), secret extraction (system prompt, credentials), and the same
attacks hidden by encoding (Base64, percent, HTML entities; two layers) or character-level disguise (look-alike letters,
accents/combining marks, spaced-out letters, leetspeak). Since Milestone 10, tool misuse and privilege abuse are addressed at the decision level for proposed agent actions
(unauthorised tools, capability confusion, self-granted privilege, agent impersonation across runtimes, critical
actions); since Milestone 11 they are enforced for the tool behind the gateway (complete mediation, argument policy,
single-use execution grants). Future milestones broaden this to: paraphrased and non-English prompt injection, credential
theft, context poisoning, enforcement for real tools, further encodings, indirect prompt injection and multi-step
jailbreaks.

## 3. Secure-by-default foundation (implemented)

| Control | Where |
|---|---|
| No exception messages, stack traces, connection strings or internal types in any HTTP response, in any environment | `GlobalExceptionHandler`, tested by `UnhandledException_Returns500WithoutLeakingInternals` |
| Health probes never expose exception or connection details | `HealthEndpoints`, tested by `UnreachableDatabase_FailsReadiness_ButNotLiveness` |
| Inbound correlation IDs validated (length + charset) to prevent log/header injection | `CorrelationIdMiddleware` |
| Secret redaction in logs (names and values, including unhandled exception text and Google `AIza…` keys) | `SensitiveDataRedactor` + `SensitiveDataRedactionEnricher`; `GlobalExceptionHandler` logs exceptions as redacted text; tested by `UnhandledException_IsLoggedWithTypeMessageAndStack_ButSecretsInItsTextAreMasked` |
| The caller-chosen request path and query never reach a log; the matched route template does | `RequestPathRemovalEnricher`, request-log properties, `EndpointNames`; tested by `CallerControlledPathAndQuery_NeverReachTheLogs_OnlyTheRouteTemplateDoes` |
| Security events cannot be silenced by the log level outside Development (startup refused); every decision is also counted in a metric | `LoggingSetup`, `LoggingSecurityEventSink`; tested by `SecurityEventsHiddenByTheLogLevel_OutsideDevelopment_FailsAtStartup`, `PublishAsync_CountsEveryDecision_EvenWhenTheAuditLogLevelIsDisabled` |
| A failing metrics listener cannot leak an AI concurrency slot or a probe slot, or stop a failure from counting | `InMemoryAiCapacityGate`, `InMemoryAiCircuitBreaker`; tested by the `MetricsListener` tests |
| Request body size limit (1 MiB default) → 413 | `ApiOptions.MaxRequestBodySizeBytes`, tested on real Kestrel by `RequestSizeLimitTests` |
| Strict JSON, one interpretation per body: duplicate, unknown and differently cased properties rejected; enums only as exact names; no string-encoded numbers, comments, trailing commas; max depth 32 (ADR 0009) | `JsonConventions`, `StrictStringEnumConverter`, tested by `JsonInputPolicyTests` |
| 400 responses for rejected JSON never name CLR types or parser internals | `AllowInputFormatterExceptionMessages = false` |
| Every convention-registered implementation of an interface is resolved (no silently dropped detectors) (ADR 0008) | `ConventionRegistrationStrategy` |
| Bounded in-memory cache (entry count limit) | `CacheOptions.SizeLimit` |
| Swagger disabled outside Development by default | `ApiOptions.SwaggerEnabled` |
| Secrets never in source; NuGet restores only from nuget.org | user-secrets / env vars; `nuget.config` |
| Configuration validated at startup | Options `ValidateOnStart` |
| Regexes used on untrusted input have timeouts; redaction fails closed on timeout | `SensitiveDataRedactor` |
| Detection regexes run in linear time (`NonBacktracking`) with a 250 ms timeout; enforced for every rule by a test | `DetectionPatterns`, `DetectorContractTests`, `ObfuscationBoundsTests` |
| Decoding and unmasking are bounded (2 layers, 16 views, 65,536 chars per view, linear, never recursive) and fail safe: content over a limit goes to Review, never silently skipped; a decoder alone never raises a finding (ADR 0011) | `ObfuscationDetector`, `ObfuscationLimits`, `ObfuscationBoundsTests` |
| Duplicate findings fused deterministically before risk (no score inflation, order independent of detectors) | `FindingAggregator`, `FindingAggregatorTests` |
| Invisible characters (format, variation selectors, CGJ) removed and Unicode compatibility forms folded (NFKC) before detection; original kept | `InputNormalizer` |
| Text hidden in the characters normalisation removes (Unicode tag characters, variation-selector runs) is read from the original and inspected by every rule, so removing it cannot hide an attack; legitimate emoji and ideographic variants stay clean (ADR 0011 amendment) | `ObfuscationDetector`, `HiddenCharacterDecoding`, `HiddenCharacterDetectionTests` |
| Firewall findings, responses and logs never contain the analysed input or content decoded from it; detector and rule IDs are logged but not returned | `ThreatFinding`, `LoggingSecurityEventSink`, tested by `Response_NeverEchoesTheInput`, `NoLogEntry_ContainsTheAnalysedInput` |
| A security decision is a 200 with `data.decision`, never an HTTP error status | `FirewallController`, tested by `PromptInjection_Returns200WithBlock_NotAnHttpError` |
| The Gemini API key is read only from `Ai:Gemini:ApiKey` (User Secrets / `Ai__Gemini__ApiKey`; committed files hold an empty placeholder), sent only in a header to a pinned endpoint, never to a host a redirect names (redirects are not followed), never logged, returned or documented in Swagger; AI off needs no key; the adapter never retries; an exception it does not map leaves it without its message | `AiOptions`, `GeminiSecurityAnalyzer`, `GeminiSecurityAnalyzerTests`, `GeminiProviderPipelineTests`, `GeminiRedirectTests` |
| AI analysis (when a provider is registered) is bounded by a hard 3 s timeout that holds even if the adapter ignores cancellation; its answer is parsed strictly (32 KiB, no unknown/duplicate members, no decision field) and validated all or nothing; model-written text never reaches a finding, response or log | `AiAssistedAnalysis`, `AiStructuredOutputParser`, `AiResponseValidator`, `AiAnalysisPipelineTests` |
| Content sent to an AI provider is the normalised text with secrets masked, never truncated; over the limit or unredactable → withheld and held for review | `RedactingAiDisclosurePolicy` (`IAiDisclosurePolicy` extension point) |
| AI failures never fail open: every failure of an expected AI analysis (timeout, outage, rate limit, open circuit, exhausted capacity, malformed/invalid answer, refusal) adds a Review finding; a deterministic Block stays Block (ADR 0016) | `AiFailurePolicy`, `AiFailurePolicyTests` |
| Every endpoint requires an authenticated client unless explicitly anonymous (fallback policy); only the health probes are anonymous (ADR 0014) | `AuthSetup`, `AuthorizationTests` |
| API keys: only SHA-256 hashes configured, constant-time comparison against every hash, one identical 401 for every failure, key never logged or echoed; the public Development key is refused at startup outside Development | `ApiKeyAuthenticationHandler`, `ApiClientRegistry`, `ApiAuthenticationOptionsValidator`, `AuthenticationTests`, `SecurityConfigurationTests` |
| Authorization by permission policies (401 vs 403), never in controllers, Application, domain or detectors | `AuthorizationPolicies`, `Permissions`, `AuthorizationTests` |
| Per-client rate limits (strict for the firewall; liveness never limited); 429 Problem Details with `Retry-After`; rate limiting cannot be disabled outside Development | `RateLimitingSetup`, `RateLimitingTests`, `AccessControlLoggingTests` |
| CORS allow-list from configuration only: no wildcard, no credentials, https only outside Development | `CorsSetup`, `CorsTests` |
| Security response headers on every response (nosniff, API CSP, frame denial, no-store); no `Server` banner | `SecurityHeadersMiddleware`, `SecurityHeadersTests`, `KestrelBoundaryTests` |
| 401/403/429 are logged with safe metadata and the request's correlation ID; authenticated log lines carry `ClientId` | `ApiKeyAuthenticationHandler`, `ClientLogContextMiddleware`, `AccessControlLoggingTests` |

## 4. Resource budget

Every resource a request can consume is bounded once, at the layer that owns it (OWASP API4 Unrestricted Resource
Consumption, LLM10 Unbounded Consumption). Limits are listed where they are enforced; none is duplicated elsewhere.

| Stage | Limit | Over the limit | Owner |
|---|---|---|---|
| Connection / headers | Kestrel defaults: 32 KiB of headers, 100 headers, 8 KiB request line | 431 / 414 (before the application) | Kestrel |
| Request rate | `Firewall` 60/min, `Standard` 300/min per client; liveness unlimited | 429 + `Retry-After` | `RateLimitingOptions` |
| Credential | API key 32–256 characters; correlation ID ≤ 64 characters | 401 / regenerated ID | `ApiKeys`, `CorrelationIdMiddleware` |
| Request body | 1 MiB | 413 | `Api:MaxRequestBodySizeBytes` (Kestrel) |
| JSON | nesting depth 32; strict shape | 400 | `JsonConventions` |
| Firewall input | 32,000 characters | 422 | `AnalyzeInputRequest.MaxInputLength` |
| Detection | `NonBacktracking` regexes, 250 ms timeout per match | 500 (fail closed) | `DetectionPatterns` |
| Decoding / unmasking | 2 layers, 16 views, 65,536 characters per view | `Obfuscation.UninspectableContent` (Review) | `ObfuscationLimits` |
| AI disclosure | 65,536 characters, never truncated | withheld → Review | `AiAnalysisLimits.MaxContentLength` |
| AI call | 3 s hard stage timeout (provider timeout 1–3 s), one attempt, 4,096 output tokens | Timeout, outage, rate limit → Review (ADR 0016) | `AiAnalysisLimits`, `AiOptions`, `GeminiRequest` |
| AI answer | 256 KiB HTTP response, 32 KiB answer text, 16 findings, 500-character descriptions | malformed/invalid → Review | `GeminiSecurityAnalyzer`, `AiStructuredOutputParser`, `AiAnalysisLimits` |
| Cache | 10,000 entries | eviction | `Cache:SizeLimit` |

## 5. Logging rules

Never log passwords, API keys, tokens/JWTs, connection strings, secrets, request bodies, raw prompts containing user
data or unnecessary PII. Log identifiers, decisions, scores, rule IDs and durations instead. Redaction is a safety net,
not permission.

## 6. Not yet implemented (tracked in PROGRESS.md)

An identity provider (OIDC/JWT) for browser users, distributed rate limiting for several instances, per-client limits
and quotas, forwarded-headers configuration for a reverse proxy, audit persistence (security events record the client
ID in logs only), and for the Gemini provider (off by default): PII handling, a paid-tier/retention review before real
user data is sent, and an evaluated prompt (the circuit breaker exists since Milestone 6). None of these may be "simulated" by the LLM.
