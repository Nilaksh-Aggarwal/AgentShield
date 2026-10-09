# API conventions

## Versioning and routing

All public endpoints live under `/api/v1/…` (`ApiRoutes.V1`). A new major version gets a new prefix; no versioning
framework is used until there is a real need. Health (`/health*`) and Swagger (`/swagger*`) are outside the prefix.

## Controllers

```csharp
[Route(ApiRoutes.V1 + "/firewall")]
[Authorize(Policy = AuthorizationPolicies.FirewallAnalyze)]
[EnableRateLimiting(RateLimitPolicies.Firewall)]
public sealed class FirewallController(IAnalyzeInputUseCase analyzeInput) : ApiControllerBase
{
    /// <summary>Analyses untrusted input and returns a security decision.</summary>
    [HttpPost("analyze")]
    [Consumes(MediaTypeNames.Application.Json)]
    [ProducesResponseType<ApiResponse<AnalysisResponse>>(StatusCodes.Status200OK, MediaTypeNames.Application.Json)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status400BadRequest, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status401Unauthorized, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status403Forbidden, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ValidationProblemDetails>(StatusCodes.Status422UnprocessableEntity, MediaTypeNames.Application.ProblemJson)]
    [ProducesResponseType<ProblemDetails>(StatusCodes.Status429TooManyRequests, MediaTypeNames.Application.ProblemJson)]
    public async Task<IActionResult> Analyze([FromBody] AnalyzeInputRequest request, CancellationToken cancellationToken) =>
        (await analyzeInput.ExecuteAsync(request, cancellationToken)).ToOkResult();
}
```

(`src/AgentShield.Api/Firewall/FirewallController.cs`. The endpoint contract is in
[firewall pipeline](../security/firewall-pipeline.md#contract).)

- Thin: bind → one use case → map the `Result`. No try/catch, no business/security logic, no data access.
- Access and throughput are **declared** by policy name (`[Authorize(Policy = …)]`, `[EnableRateLimiting(…)]`); the
  policies are defined once in `AuthSetup` / `RateLimitingSetup`. No role or permission checks in controller code.
- `ApiControllerBase` adds `[ApiController]`, the `Standard` rate-limit policy (a controller's own
  `[EnableRateLimiting]` replaces it) and documents the 500 Problem Details response. Every controller requires an
  authenticated client through the fallback policy; `[AllowAnonymous]` is an explicit, reviewed exception.
- **Never add `[Produces]` at controller level** — it is a result filter that rewrites every `ObjectResult`'s content
  type, turning `application/problem+json` into `application/json`.

## Successful responses

```json
{
  "data": { "decision": "Block", "risk": { "level": "High", "score": 75 } },
  "meta": { "correlationId": "5f0c…", "timestamp": "2026-09-29T05:42:14.26+00:00" }
}
```

| Helper | Status | Body |
|---|---|---|
| `result.ToOkResult()` | 200 OK | envelope |
| `result.ToCreatedResult(v => location)` | 201 Created + `Location` | envelope |
| `result.ToAcceptedResult(v => statusUrl?)` | 202 Accepted (+ optional `Location`) | envelope |
| `result.ToNoContentResult()` | 204 No Content | none |

There is no `success` flag: the status code conveys the outcome, and failures are never enveloped.

## Error responses — RFC 9457 Problem Details

Content type `application/problem+json`:

```json
{
  "type": "https://tools.ietf.org/html/rfc9110#section-15.5.10",
  "title": "Conflict",
  "status": 409,
  "detail": "A policy with this name already exists.",
  "instance": "/api/v1/policies",
  "errorCode": "Policy.DuplicateName",
  "correlationId": "5f0c…",
  "timestamp": "2026-09-29T05:42:14.26+00:00",
  "traceId": "00-…"
}
```

Validation (422) uses `ValidationProblemDetails` with camelCase field paths:

```json
{
  "status": 422,
  "title": "One or more validation errors occurred.",
  "errorCode": "Validation.Failed",
  "errors": { "content": ["'Content' must not be empty."], "items[0].displayName": ["…"] },
  "correlationId": "…", "timestamp": "…"
}
```

When a failed `Result` carries several non-validation errors, the first decides the status/`errorCode`/`detail`
and all are listed in `errors: [{ code, message }]`. `Error.Metadata` is never serialised.

## Status code conventions

| Status | When | Produced by |
|---|---|---|
| 200 OK | Operation performed (including an analysis that decided BLOCK) | `ToOkResult` |
| 201 Created | Resource created | `ToCreatedResult` |
| 202 Accepted | Work continues asynchronously | `ToAcceptedResult` |
| 204 No Content | Success without body | `ToNoContentResult` |
| 400 Bad Request | Malformed JSON, wrong JSON types, duplicate/unknown properties, invalid enum names, unbindable request | MVC model binding (strict JSON, ADR 0009) |
| 401 Unauthorized | No valid credential: missing, malformed, repeated or unknown `X-API-Key` (identical response for all; `WWW-Authenticate: ApiKey`) | API key handler → status-code pages / `ErrorType.Unauthorized` |
| 403 Forbidden | Valid credential without the endpoint's permission | authorization policy → status-code pages / `ErrorType.Forbidden` |
| 404 Not Found | Unknown route or resource | status-code pages / `ErrorType.NotFound` |
| 405 Method Not Allowed | Wrong HTTP method | routing |
| 409 Conflict | State conflict | `ErrorType.Conflict` |
| 413 Content Too Large | Body exceeds `Api:MaxRequestBodySizeBytes` (1 MiB) | Kestrel → exception handler |
| 415 Unsupported Media Type | Wrong `Content-Type` on an action with `[Consumes]` | MVC |
| 422 Unprocessable Content | Well-formed but invalid input; business-rule violation | validators / `ErrorType.Validation`, `ErrorType.BusinessRule` |
| 429 Too Many Requests | Client exceeded its rate limit; `Retry-After` in seconds | ASP.NET Core rate limiter (`RateLimitingSetup`) |
| 500 Internal Server Error | Unexpected failure | exception handler / `ErrorType.Unexpected` |
| 502 Bad Gateway | External dependency failed or returned garbage | `ErrorType.ExternalDependency` |
| 503 Service Unavailable | Not ready (e.g. readiness failing) | health checks / future overload protection |
| 504 Gateway Timeout | Upstream timed out | reserved for dependency timeouts |

No custom status codes. **A security decision is not an HTTP status**: `POST /api/v1/firewall/analyze` answers 200
with `data.decision = "Block"` when the analysis itself succeeded.

Order of checks for a protected endpoint (each stops the request): CORS preflight (answered without credentials) →
401 → 403 → 429 → 415 / 400 (body) → 422 (validator) → 200 or 500. So an anonymous caller learns nothing about the body
rules, and an anonymous request to an unknown route or with the wrong method also gets 401 (authenticated callers get
404/405). Health probes are anonymous and answer 200/503 by health status.

### Default `errorCode` values

Framework-produced problems receive a default code by status: `Request.Malformed` (400), `Auth.Unauthenticated` (401),
`Auth.Forbidden` (403), `Resource.NotFound` (404), `Request.MethodNotAllowed` (405), `Resource.Conflict` (409),
`Request.TooLarge` (413), `Request.UnsupportedMediaType` (415), `Validation.Failed` (422), `Request.RateLimited` (429),
`Server.Unexpected` (500), `Dependency.Failed` (502), `Server.Unavailable` (503), `Dependency.Timeout` (504).
Application errors use their own `Error.Code`.

## Validation

- FluentValidation validators live in Application next to the request DTO (`AbstractValidator<TRequest>`), and are
  registered automatically by `AddApplication()`.
- `FluentValidationActionFilter` runs every validator for each action argument **before** the action; failures
  return 422 and the use case never runs. Do not re-validate in controllers or duplicate rules in services.
- MVC's implicit `[Required]` for non-nullable reference types is disabled, so "required" is a validator rule (→ 422)
  and 400 stays reserved for malformed requests.
- Frontend validation exists for UX only; the backend is authoritative.

## JSON

Configured once in `JsonConventions`; controllers never customise serialisation. Request bodies are read strictly
(ADR 0009), and each rule below gives **400 `Request.Malformed`**:

- property names are camelCase and matched exactly (`"Input"` is unknown);
- duplicate properties (`{"input":"a","input":"b"}`) at any depth;
- unknown properties;
- enum values other than the exact declared name (`"Block"`; not `999`, `"1"`, `"block"` or `"Block, Sanitize"`);
- numbers in strings, comments, trailing commas, multiple top-level values, nesting deeper than 32, wrong JSON types.

The 400 `errors` object is keyed by JSON path (`"$.input"`) with a generic message; it never contains CLR type names.

**Request DTO rule:** declare every member the client may omit as nullable (`string?`, `int?`) and enforce presence in
the validator, so both a missing member and `null` produce **422** with a field error. Do not use `[JsonRequired]` or
C# `required` on request DTOs (they turn "missing" into 400). A non-nullable value-type member receiving `null` is a
JSON type error (400).

## Query parameters

Bound with `[FromQuery]` into a request type in Application, validated like a body (422). First user:
`GET /api/v1/activity` ([ADR 0019](../decisions/0019-security-activity-history.md)).

- Parameter names are camelCase in the OpenAPI document; binding matches them case-insensitively (standard MVC).
  Unknown parameters are ignored; a repeated scalar takes its first value; a list parameter is repeated
  (`?decision=Review&decision=Block`).
- **Enum-like values are bound as text** and accepted only as exact declared names by the validator (422 otherwise):
  MVC's query-string enum binder would also accept numbers, other casings and comma lists (`3`, `block`,
  `Block,Allow`), the leniency ADR 0009 removed from JSON.
- **Bounds are validator rules**: every page size or count has a maximum and a default; nothing is unlimited.
- A value that does not bind to its type (`?page=abc`) is a **400** that names the field and never quotes the value
  (D-19: MVC's default message echoed it). Validator messages list the accepted values, never the rejected one.

| Parameter (`GET /api/v1/activity`) | Accepted | Default |
|---|---|---|
| `page` | 1–100,000 (an empty page after the last one is a 200) | 1 |
| `pageSize` | 1–100 | 25 |
| `decision` | `Allow`, `Review`, `Block`; repeat for several, at most 3 values | every decision |
| `minRiskLevel` | `Low`, `Medium`, `High`, `Critical` | every level |

`GET /api/v1/activity/summary` (Milestone 12, [ADR 0022](../decisions/0022-attack-lab-demonstration-layer.md)) takes
no parameters and returns counts only, from one read of the history: `totalCount`, `oldestOccurredAt` and
`newestOccurredAt` (`null` when empty), `decisions` (`allow`, `review`, `block`), `kinds` (`inputAnalysis`,
`agentActionAuthorization`, `toolExecution`) and `toolsExecuted` (tool calls whose tool ran). Same permission
(`activity:read`) and rate limit (`Standard`) as the list. The counts describe this process's bounded, in-memory history,
not a period.

## Authentication and authorization

Decision record: [ADR 0014](../decisions/0014-api-boundary-hardening.md).

- **Credential:** an API key in the `X-API-Key` header (scheme `ApiKey`). Keys are ≥ 32 characters of
  `[A-Za-z0-9-._~]`; generate one with `scripts/new-api-key.ps1`. `Authorization: Bearer …` is not accepted (yet).
- **Configuration** (`Authentication:Clients:{clientId}`): `KeyHashes` (SHA-256 hex of each valid key; several allow
  rotation) and `Permissions`. Only hashes are configured. Production clients come from environment variables or a
  secret store, e.g. `Authentication__Clients__billing-agent__KeyHashes__0=<hash>` and
  `Authentication__Clients__billing-agent__Permissions__0=firewall:analyze`. The committed `appsettings.json` has none
  (startup logs a warning; every protected endpoint then answers 401).
- **Validated at startup:** client IDs (lower-case, ≤ 64 characters), hash format, one client per hash, known
  permissions, and the public Development key hash is refused outside Development.
- **Permissions → policies:** `firewall:analyze` → policy `FirewallAnalyze` (the analyze endpoint); `activity:read` →
  policy `ActivityRead` (the activity history, an operator permission: it shows every client's decisions, so firewall
  clients should not hold it); `agent:authorize` → policy `AgentAuthorize` (the agent action authorization endpoint, for
  the runtime that executes an agent's tool calls; it grants nothing else); `tool:execute` → policy `ToolExecute` (the tool
  gateway, for an agent's own credential: the client must be exactly one agent's `GatewayClient` and acts as that agent
  only; it grants nothing else); `agent:approve` → policy `AgentApprove` (the approval endpoints, for the console a
  person uses to decide held tool calls; it grants nothing else; outside Development a client holding it may hold neither
  `tool:execute` nor `agent:authorize`, so an agent cannot approve its own calls). Any other endpoint requires an authenticated
  client (fallback policy). Anonymous:
  `/health/live`, `/health/ready`, `/health`.
- **Development only:** `appsettings.Development.json` registers the client `development` with the public key
  `agentshield-development-only-key-not-a-secret` (permissions `firewall:analyze`, `activity:read`, `agent:authorize`,
  `tool:execute` and `agent:approve`, so the local console can analyse, show the history, run the agent authorization and
  tool gateway previews and decide held calls — self-approval is therefore possible in Development only; the demo agents are bound to it, and it is research-agent's gateway identity). It is not a secret and not a bypass:
  it goes through the same handler and policies, the file is not loaded in other environments, and startup fails if its
  hash is configured anywhere else. The Vite dev proxy and `scripts/gemini-smoke.ps1` send it.
- **Logs:** 401 → warning with the reason category (`MissingKey`, `MalformedKey`, `UnknownKey`), method and route
  template; 403 → warning with the client ID. Never the key or header. Authenticated requests carry `ClientId` on every
  log line (security events included).

## Agent action authorization

`POST /api/v1/agent/actions/authorize` (permission `agent:authorize`) decides whether an agent may perform a tool action;
it executes nothing. Body: `agentId`, `tool`, `action`, `capability` (required, exact lower-case names; a capability
is `resource:operation`) and optional `inputDecision` (`Allow`, `Review`, `Block`). Any other property → 400; a
missing or inexact name → 422 (the message describes the format, never the value). Response: `data` = `securityEventId`,
`decision`, `riskLevel`, `reason` — 200 whatever the decision. Only `Allow` permits running the action; Review, Block,
any 4xx and any 5xx mean it must not run. Agents are configured in `AgentAuthorization:Agents:{agentId}`
(`Capabilities`, `Clients`); a client gets decisions only for the agents bound to it. Specification:
[agent-action-authorization.md](../security/agent-action-authorization.md).

## Tool gateway

`POST /api/v1/agent/tools/execute` (permission `tool:execute`) runs a tool action for the agent the API key identifies,
only on the authorization boundary's Allow, or on its Review when the request presents an approval of exactly this call.
Body: `tool`, `action`, `capability` (required, exact names) and `arguments` (required, a JSON object), optional
`inputDecision`, optional `inputEventId` (the `securityEventId` of the firewall analysis of the input behind the call; it
must be this client's, in this trace — same `X-Correlation-ID` — and at most 10 minutes old, else Block
`InputContextRejected`), optional `approvalId`. There is no agent field: the agent is the client's
gateway identity (`AgentAuthorization:Agents:{agentId}:GatewayClient`). Any other property → 400; a missing or inexact
name, or `arguments` that is not an object → 422. Response: `data` = `securityEventId`, `decision`, `executed`,
`outcome`, `authorizationReason`, `riskLevel`, `executionId`, `result` (`found`, `text`), `approvalId` — 200 whatever was decided.
Only `Allow` with `executed: true` means the tool ran; arguments the tool's argument policy rejects are a Block
(`ArgumentsRejected`). The one executable tool is `knowledge.lookup` (`knowledge:read`, `{ "query": "1–200 characters" }`).
Specification: [tool-gateway.md](../security/tool-gateway.md).

## Tool approvals

A Review the gateway holds, for an action a tool here runs, gets a pending approval (`approvalId` in the response).
`GET /api/v1/agent/approvals` (newest 50), `POST /api/v1/agent/approvals/{approvalId}/approve` and `/deny` (permission
`agent:approve`, no request body: any body is ignored, nothing in it is authority). Response `data` = `approvalId`,
`status` (`Pending`, `Approved`, `Denied`, `Expired`, `Used`), `securityEventId` and `correlationId` of the held
request, `agentId`, `tool`, `action`, `capability`, `riskLevel`, `reason`, `inputDecision`, `requestedAt`, `expiresAt`,
`decidedAt` — never the arguments, their digest or a client. Errors: 400 for an ID that is not a GUID, 404 `Approval.NotFound`
(the ID is never quoted in a message), 409 `Approval.AlreadyDecided`, 409 `Approval.Expired`. An approved call runs when the agent sends the same
call with `approvalId` to the gateway, once, before `expiresAt` (`ToolApprovals:LifetimeSeconds`, default 600).
Specification: [tool-gateway.md](../security/tool-gateway.md) section 16.

## Rate limiting

In-memory fixed windows per client (ASP.NET Core rate limiter), section `RateLimiting`:

| Policy | Applies to | Production (`appsettings.json`) | Development |
|---|---|---|---|
| `Firewall` | `POST /api/v1/firewall/analyze` | 60 requests / 60 s per client | 600 / 60 s |
| `Standard` | every other controller (incl. `POST /api/v1/agent/actions/authorize`, `POST /api/v1/agent/tools/execute`, the approval endpoints, `GET /api/v1/activity` and `GET /api/v1/activity/summary`), `/health/ready`, `/health` | 300 / 60 s per client | 3000 / 60 s |
| none | `/health/live` | never limited | never limited |

- The partition is the authenticated client ID (the remote address for anonymous endpoints). The limiter runs after
  authorization: 401/403 responses never consume a client's budget.
- Over the limit → **429** Problem Details (`Request.RateLimited`) with `Retry-After` (seconds). The body names no
  policy, limit or partition. A warning log records policy, route template, client ID and correlation ID.
- `QueueLimit` 0 (default) rejects at once. `Enabled=false` is accepted only in Development; any other environment
  refuses to start. Limits are validated (permit 1–100,000; window 1–3,600 s; queue 0–100).
- Why not Redis yet, and the distributed path: [ADR 0014](../decisions/0014-api-boundary-hardening.md).

## CORS

- Only origins in `Cors:AllowedOrigins` (exact `scheme://host[:port]`; no `*`, path or trailing slash; https only
  outside Development; validated at startup). Production default: none. Development: `http://localhost:5173` (only
  needed when the frontend calls the API directly; the Vite proxy is same-origin).
- Methods `GET`, `POST`; request headers `Accept`, `Content-Type`, `X-Correlation-ID`; exposed headers
  `X-Correlation-ID`, `Retry-After`; no credentials; preflight cached 10 minutes.
- A preflight is answered before authentication (it carries no credentials). CORS is a browser rule, not access
  control: a disallowed origin simply receives no `Access-Control-Allow-*` headers.

## Security headers

Set on every response, errors included (`SecurityHeadersMiddleware`), following the OWASP REST Security Cheat Sheet:

| Header | Value | Why |
|---|---|---|
| `X-Content-Type-Options` | `nosniff` | A browser never reinterprets JSON as HTML or script |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | A rendered response loads nothing and cannot be framed (API policy, not a frontend CSP) |
| `X-Frame-Options` | `DENY` | Framing protection for browsers without CSP `frame-ancestors` |
| `Cache-Control` | `no-store` (unless the endpoint sets its own, e.g. health) | Analyses and errors are never stored by browser or shared caches |
| `Strict-Transport-Security` | ASP.NET Core defaults, outside Development, on HTTPS responses | Browsers keep using HTTPS |

Not sent: `Server` (removed in Kestrel options), `X-Powered-By` (not produced). Evaluated and **not** added:
`Referrer-Policy` and `Permissions-Policy`, which govern documents a browser renders; the API renders none. The
Development-only Swagger UI (`/swagger*`) is an HTML app and gets only `nosniff`, so it keeps working.

## HTTPS and deployment

- Outside Development: HSTS and `UseHttpsRedirection` (existing). Redirection is a fallback only: a client that first
  calls `http://` has already sent its API key in clear text. **Production must expose HTTPS only** (Kestrel HTTPS
  endpoint or a TLS-terminating reverse proxy with no plain-HTTP listener reaching the API). Certificates are managed by
  the host/proxy, not by the application.
- Forwarded headers are **not** processed. Behind a proxy, configure `ForwardedHeadersOptions` with `KnownProxies` /
  `KnownNetworks` first; trusting `X-Forwarded-For` from anyone would let clients choose their rate-limit partition and
  spoof the scheme.
- Set `AllowedHosts` to the public host names (the committed value `*` accepts any `Host`).
- Tests run over plain HTTP in the Development environment, where neither HSTS nor redirection applies.

## OpenAPI / Swagger

Swashbuckle generates `/swagger/v1/swagger.json` and Swagger UI at `/swagger` from controllers, XML doc comments
(`GenerateDocumentationFile`) and `[ProducesResponseType]`/`[Consumes]` metadata. Served by default in the
Development environment (derived from the environment, not from a settings file); disabled elsewhere unless
`Api:SwaggerEnabled=true`. An explicit `Api:SwaggerEnabled` value overrides the environment either way. Never
put secrets, internal hostnames or exception details in doc comments or examples.

The document declares the `ApiKey` security scheme (header `X-API-Key`) and, through
`SecurityRequirementsOperationFilter`, requires it on every operation that is not `[AllowAnonymous]`, naming the
authorization policy in the description. Responses 401/403/429 are documented with `[ProducesResponseType]`. No key
value, example or default is ever in the document; in Development use **Authorize** in Swagger UI with the
Development key above. The Swagger UI is middleware (not an endpoint), so it is not behind authentication or rate
limiting; it is off outside Development.

## Frontend client

`src/services/api/apiClient.ts` is the only HTTP entry point (ESLint bans `fetch` elsewhere):

- base URL from `VITE_API_BASE_URL` (empty = same origin via the Vite dev proxy);
- JSON serialisation; unwraps `{ data, meta }` (pass `envelope: false` for `/health`);
- sends a fresh `X-Correlation-ID` per request;
- `setAccessTokenProvider()` is the hook for future identity-provider authentication (adds `Authorization: Bearer`);
  the API does not accept bearer tokens yet. In development the **Vite proxy** adds `X-API-Key` (the public Development
  key, or `AGENTSHIELD_DEV_API_KEY`) server-side, so no key is in the browser bundle. A production browser frontend
  needs a real identity provider: a browser cannot keep an API key secret;
- timeout (15 s default) combined with caller cancellation (`AbortSignal.any`);
- every failure becomes an `ApiError` (`kind`: http / network / timeout / aborted / invalid-response) with `status`,
  `errorCode`, `correlationId`, `fieldErrors` and a safe `userMessage`. Raw server text is never rendered.

TanStack Query retries only transient failures (network, timeout, 502/503/504) and never retries mutations.
