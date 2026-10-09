# Cross-cutting concerns

## Dependency injection (Microsoft DI + Scrutor)

Each layer exposes one registration entry point, called from `Program.cs`:

```csharp
builder.Services
    .AddApplication()                          // marked services + FluentValidation validators
    .AddInfrastructure(builder.Configuration)  // options, IMemoryCache, ICacheService, DbContext (if configured)
    .AddAI(builder.Configuration)             // AiAnalysis options; Gemini typed client only when enabled
    .AddSecurity()
    .AddApiPresentation(builder.Configuration); // MVC, JSON, Problem Details, logging, Swagger, health
```

**Convention registration is opt-in.** A class implements a lifetime marker from
`Application/Abstractions/DependencyInjection`:

```csharp
internal sealed partial class ObfuscationDetector : IThreatDetector, ISingletonService { ... }
```

`AddMarkedServices(assembly)` (Scrutor) registers it against every interface it implements except the marker, with the
marker's lifetime (ADR 0008):

- every implementation of a shared interface is registered and resolves through `IEnumerable<T>` (several
  `IThreatDetector`s all run);
- an implementation is never registered twice for the same interface (re-scans and explicit duplicates are ignored);
- an explicit registration wins `GetService<T>()` whether made before or after the scan. The marked implementation
  stays in `IEnumerable<T>`; remove the marker to exclude a class entirely.

**Register explicitly** (in the layer's `DependencyInjection.cs`) when a service needs configuration, a special
lifetime, keyed registration, an `HttpClient`, a `DbContext` or framework setup. Example: `MemoryCacheService` is
registered explicitly as a singleton because it depends on options and shares `IMemoryCache`.

Development builds the container with `ValidateOnBuild` + `ValidateScopes`; the integration tests boot the host in
Development, so a broken DI graph fails the build pipeline.

## Configuration (Options pattern)

| Options class | Section | Validated at startup |
|---|---|---|
| `ApiOptions` (Api) | `Api` | `MaxRequestBodySizeBytes > 0` |
| `CacheOptions` (Infrastructure) | `Cache` | positive `DefaultExpiration`, `SizeLimit` |
| `DatabaseOptions` (Infrastructure) | `Database` | `CommandTimeoutSeconds` 1–600 |
| `AiOptions` (AI) | `Ai` (+ `Ai:Gemini`) | `Provider` = `Gemini`; `Model` lower-case letters/digits/`.`/`-`; `TimeoutSeconds` 1–3; key present when `Enabled` |
| Gemini API key | `Ai:Gemini:ApiKey`: User Secrets (Development) or `Ai__Gemini__ApiKey`; committed files hold `""` | required only when `Ai:Enabled` is true |
| Connection string | `ConnectionStrings:AgentShield` | optional (see persistence) |
| `ApiAuthenticationOptions` (Api) | `Authentication:Clients:{clientId}` (`KeyHashes`, `Permissions`) | client ID format, SHA-256 hash format, one client per hash, known permissions, Development key refused outside Development (`ApiAuthenticationOptionsValidator`) |
| `RateLimitingOptions` (Api) | `RateLimiting` (`Enabled`, `Firewall`, `Standard`) | permit 1–100,000, window 1–3,600 s, queue 0–100; `Enabled=false` only in Development |
| `ApiCorsOptions` (Api) | `Cors:AllowedOrigins` | exact origins, no wildcard/path; https only outside Development |

Pattern: `AddOptions<T>().Bind(section).Validate(...).ValidateOnStart()`. Invalid configuration stops the host at
startup (covered by `CompositionTests.InvalidConfiguration_FailsAtStartup`). Secrets come from user-secrets or
environment variables, never from committed `appsettings*.json`.

## Logging (Serilog behind Microsoft.Extensions.Logging)

- Application code uses `ILogger<T>` and message templates only.
- Serilog is configured from the `Serilog` section: compact JSON to console by default; readable console + rolling
  JSON files in `logs/` for Development.
- Enrichers: log context (`CorrelationId`), `Application`, `RequestPathRemovalEnricher` (drops the raw `RequestPath` that
  ASP.NET Core's request scope adds to every event: the caller chooses the path), and **`SensitiveDataRedactionEnricher`
  last**.
- Request logging (`UseSerilogRequestLogging`) writes one line per request with the method, the matched route template
  (`Endpoint`, `(unmatched)` otherwise), status and duration, never the raw path or query; `/health*` requests are logged
  at Verbose to avoid noise.
- Security events are the audit trail: outside Development the API refuses to start if the log level would hide them
  (Information for `AgentShield.Infrastructure.SecurityEvents`); Development only warns. They are also counted in the
  `agentshield.security_events` metric, whether or not the log entry is written.
- The logger is owned by the host (`preserveStaticLogger: true`); a minimal console logger reports fatal startup errors.

### Redaction

`AgentShield.Security.Redaction.SensitiveDataRedactor` is pure and framework-free; the API's Serilog enricher applies
it to every property at any depth:

- property names whose **last word** denotes a secret (`Password`, `ApiKey`, `AccessToken`, `ClientSecret`,
  `ConnectionString`, `Authorization`, `Cookie`, …) are masked entirely (`***REDACTED***`);
- string values are scanned for bearer tokens, JWTs, credential assignments (`password=…`) and well-known API key
  formats (`sk-…`, `AKIA…`, `ghp_…`, Google `AIza…`).

Descriptors such as `ConnectionStringName` or `PromptTokens` are not masked. The enricher cannot rewrite exception
objects, so `GlobalExceptionHandler` logs an unhandled exception as text (`ExceptionDetail`: type, message, inner
exceptions, stack trace), which passes the redactor. The Gemini adapter goes further: an exception it does not map leaves
it as `GeminiAdapterFaultException`, with type names and stack trace but never the original message (which can carry
provider-chosen text). Redaction is defence in depth — do not log sensitive data at all.

## Correlation ID

Header `X-Correlation-ID`. `CorrelationIdMiddleware` (first in the pipeline):

1. accepts an inbound value only if it is ≤ 64 chars of `[A-Za-z0-9._:-]` (prevents log/header injection);
2. otherwise generates a 32-hex-character ID;
3. stores it on `HttpContext` (`HttpContext.GetCorrelationId()`), pushes it into the Serilog log context and
   echoes it on the response via `OnStarting` (so error responses keep it after the exception handler clears headers).

The same value appears in the response header, the success envelope `meta.correlationId`, Problem Details
`correlationId` (including 401, 403 and 429), and every log line for the request (including the authentication,
authorization and rate-limit warnings). The W3C `traceId` is kept separately for distributed tracing. After
authentication, `ClientLogContextMiddleware` adds `ClientId` the same way (never the key).

`SecurityEventId` (Domain) is a different concept: a UUIDv7 identity for a security event. One request may raise
zero or many security events.

Use cases read the correlation ID through `ICorrelationContext` (Application port; `HttpCorrelationContext` in Api,
registered explicitly with `AddHttpContextAccessor`), e.g. to stamp `SecurityEvent.CorrelationId`.

## Error handling

- Expected failures: `Result`/`Error` → mapped centrally (see [API conventions](../api/conventions.md)).
- Unexpected exceptions: `GlobalExceptionHandler` (`IExceptionHandler`) logs once (as redacted text, with the route
  template, never the raw path) and writes Problem Details through `IProblemDetailsService`. Response never contains the exception message, type or stack trace — in any environment.
  `BadHttpRequestException` keeps its status (e.g. 413 body too large). A client-cancelled request is logged at
  Information and not answered.
- `AddProblemDetails` + `UseStatusCodePages` turn bodiless error statuses (401 challenge, 403 forbid, 404 route not
  found, 405) into Problem Details. The rate limiter writes its 429 Problem Details itself (with `Retry-After`).
- `ProblemDetailsCustomization` adds `correlationId`, `timestamp`, a default `errorCode` and `instance` to every
  Problem Details regardless of which component produced it.

## Health checks

| Endpoint | Checks | Notes |
|---|---|---|
| `/health/live` | tag `live` (`self`) | Never includes dependencies — a DB outage must not restart the process |
| `/health/ready` | tag `ready` (`postgresql` when configured) | 503 when a dependency is unhealthy |
| `/health` | all | Overall view |

Responses are JSON `{ status, totalDurationMs, checks[] }`, uncached, and never include exception details or
connection information. Layers register their own checks with `HealthCheckTags.Ready`.

All three are anonymous (orchestrators hold no API key). `/health/live` is never rate limited; `/health/ready` and
`/health` use the generous `Standard` limit. There is deliberately **no AI/Gemini health check**: AI is optional and a
provider outage holds inputs for review (the circuit breaker stops calling), so Gemini being unavailable never makes the
API unready or dead (tested by `UnavailableGemini_LeavesLivenessAndReadinessHealthy_AndAnalysisDeterministic`, whose
input is a deterministic Block).

## API boundary: authentication, authorization, rate limiting, CORS, headers

Presentation-only concerns in `AgentShield.Api` (`Auth/`, `RateLimiting/`, `Cors/`, `Http/SecurityHeadersMiddleware`),
built on ASP.NET Core's own authentication, authorization, rate limiting and CORS; no extra package. Contract and
configuration: [API conventions](../api/conventions.md#authentication-and-authorization); decisions and future path
(identity provider, distributed rate limiting): [ADR 0014](../decisions/0014-api-boundary-hardening.md). Rate-limit
state is in memory, per process: fine for the current single instance, not for several.

## Caching

`ICacheService` (Application) is the only cache API application code may use. `MemoryCacheService`
(Infrastructure) implements it over `IMemoryCache`:

- asynchronous signatures so a distributed implementation can replace it without touching callers;
- every entry has size 1 and the cache has a `SizeLimit` (default 10 000) — bounded memory against cache flooding;
- default absolute expiration from `Cache:DefaultExpiration` (5 min) unless the caller sets one;
- `GetOrCreateAsync` does not coalesce concurrent misses: factories must be idempotent.

Redis is intentionally not used at this stage.

## Persistence

`AgentShieldDbContext` (schema `agentshield`) and the Npgsql provider are wired in Infrastructure but **only when
`ConnectionStrings:AgentShield` is set**; otherwise persistence is disabled, a startup warning is logged and
readiness does not check PostgreSQL. No entities exist yet: tables arrive with the feature that needs them
(each with an `IEntityTypeConfiguration<T>` and an EF Core migration). See ADR 0005.

## HTTP clients and resilience

The only outbound HTTP is the Gemini adapter (Milestone 4): a typed client (`AddHttpClient<IAiSecurityAnalyzer,
GeminiSecurityAnalyzer>` in `AddAI`) with an explicit timeout (`Ai:TimeoutSeconds`), a 256 KiB response cap and
**no** resilience handler; the Google.GenAI SDK receives the typed `HttpClient` and its own retry is pinned to one
attempt. Redirects are not followed (`AllowAutoRedirect = false` on the primary handler): .NET would send the
`x-goog-api-key` header again to whatever host a redirect named. Rules for any outbound HTTP (LLM providers, webhooks):

- register **typed clients** through `IHttpClientFactory` in the owning layer (`AI` for LLM providers);
- set explicit timeouts and pass `CancellationToken` through;
- add `Microsoft.Extensions.Http.Resilience` only when a client needs it (none does yet), and configure retries
  **only for idempotent requests**. LLM completion calls, tool executions and any POST with side effects must not be
  retried automatically; prefer a timeout + circuit breaker and surface `ErrorType.ExternalDependency` (→ 502).
- AI provider adapters (`IAiSecurityAnalyzer`) are the exception to the 502 mapping: they report failures with
  `AiAnalysisErrors`, and the AI analysis stage turns them into an audit status and, where the input may have caused
  the failure, a Review finding. The analysis still returns 200. The stage enforces its own 3 s timeout on top of the
  adapter's (docs/security/ai-analysis.md).

## JSON

Configured once in `JsonConventions` for both MVC and the HTTP pipeline (ADR 0009): camelCase properties matched
exactly, duplicate and unknown properties rejected, enums as exact declared names only (`StrictStringEnumConverter`),
strict number handling (`"42"` is not a number), no comments or trailing commas, maximum depth 32. Rejected bodies get
a 400 whose `errors` are keyed by JSON path with a generic message (no CLR type names). Missing or `null` members are
left to validators (422).

## Async and cancellation

I/O is async end to end; `CancellationToken` flows from `HttpContext.RequestAborted` through use cases to adapters.
No `.Result`, `.Wait()`, or `Task.Run` wrappers around I/O.
