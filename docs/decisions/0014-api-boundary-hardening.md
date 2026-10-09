# ADR 0014: API boundary hardening — API key authentication, permission policies, in-memory rate limiting, CORS allow-list, security headers

- Status: Accepted (Milestone 5)
- Date: 2026-09-30

## Context

Until Milestone 5 every endpoint was anonymous and unlimited. The firewall endpoint runs CPU-bound detection and, when
AI is enabled, a paid provider call, so it is both a target for abuse and a cost amplifier (OWASP API Security Top 10
2023: API2 Broken Authentication, API4 Unrestricted Resource Consumption, API5 Broken Function Level Authorization, API8
Security Misconfiguration; OWASP Top 10 for LLM Applications 2025: LLM10 Unbounded Consumption).

Constraints: no external identity provider exists; the application runs as one instance; no Redis or other distributed
infrastructure without an ADR; local development (API, Vite frontend, Swagger, smoke script) must stay easy; nothing may
bypass authorization in Production; built-in ASP.NET Core features are preferred over packages.

## Decision

1. **Authentication: API keys through the ASP.NET Core authentication system.** `ApiKeyAuthenticationHandler` is a
   standard `AuthenticationHandler` for the scheme `ApiKey`, reading the `X-API-Key` header. Configuration
   (`Authentication:Clients:{clientId}`) holds only SHA-256 hashes of keys (several per client, for rotation) and the
   client's permissions; keys are ≥ 32 characters from the base64url alphabet (`scripts/new-api-key.ps1` generates
   32 random bytes). Lookup hashes the presented key and compares it with every configured hash in constant time. A
   missing, malformed, duplicated or unknown key gives the same 401 (`WWW-Authenticate: ApiKey`); the log records the
   reason category only. Unsalted SHA-256 is sufficient because keys are random with ≥ 256 bits of entropy (unlike
   passwords, they cannot be brute-forced from the hash).
2. **Authorization: named permission policies, secure by default.** Policies require permission claims
   (`permission = firewall:analyze`), never client IDs or schemes. `FirewallAnalyze` protects the analyze endpoint; the
   **fallback policy requires an authenticated client on every endpoint**, so a new endpoint is protected unless it
   opts out with `AllowAnonymous` (only the health probes do). Controllers declare the policy name with
   `[Authorize(Policy = ...)]`; no role check or authorization logic lives in controllers, the Application layer, the
   domain or detectors. 401 = no valid credential; 403 = valid credential without the permission. Both are Problem
   Details (`Auth.Unauthenticated`, `Auth.Forbidden`) produced by the existing status-code pages.
3. **Development access: a public, Development-only key, not a bypass.** `appsettings.Development.json` registers the
   client `development` with the hash of the documented key `agentshield-development-only-key-not-a-secret`. Every
   request, in every environment, goes through the same handler and policies. Outside Development the key does not
   exist (the file is not loaded), and startup fails if any client is configured with its hash. The Vite dev proxy adds
   the key server-side (never in the browser bundle); the Gemini smoke script sends it.
4. **Rate limiting: built-in ASP.NET Core rate limiter, in-memory fixed windows per client.** Policies `Firewall`
   (strict; 60/min in production, 600/min in Development) and `Standard` (300/min; 3000/min in Development) from
   `RateLimiting` options, validated at startup (`Enabled` may be false only in Development). The partition key is the
   authenticated client ID (the remote address for anonymous endpoints). `UseRateLimiter` runs after authorization, so
   401/403 never consume a client's budget and limits follow identity, not IP. Every controller inherits `Standard`
   from `ApiControllerBase`; the firewall controller replaces it with `Firewall`; `/health/live` is never limited.
   Rejections are 429 Problem Details with `Retry-After` and a warning log (policy, endpoint template, client ID,
   correlation ID). `QueueLimit` defaults to 0: queued requests hold connections.
5. **CORS: explicit allow-list.** Origins only from `Cors:AllowedOrigins` (exact `scheme://host[:port]`; no wildcard;
   https only outside Development; validated at startup). Empty in production by default. Methods GET/POST, request
   headers `Accept`, `Content-Type`, `X-Correlation-ID`; exposes `X-Correlation-ID` and `Retry-After`; no credentials
   (the API uses no cookies). The dev frontend uses the Vite proxy (same origin), so CORS is not on its path.
6. **Security headers for a JSON API** (OWASP REST Security Cheat Sheet): `X-Content-Type-Options: nosniff`,
   `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`, `X-Frame-Options: DENY`,
   `Cache-Control: no-store`, HSTS outside Development (existing), no `Server` header. Referrer-Policy and
   Permissions-Policy are **not** added: they govern documents a browser renders, and the API serves none (the
   Development-only Swagger UI keeps browser defaults and gets only `nosniff`).

## Why not …

- **JWT bearer with a self-issued signing key:** needs `Microsoft.AspNetCore.Authentication.JwtBearer` (a package),
  token issuance and key management, and would be a home-made identity provider. API keys fit the actual callers
  (agents and services calling a firewall) and the handler/policy design lets a real IdP scheme be added later without
  touching endpoints.
- **A Development "anonymous = admin" principal:** it would make the Development pipeline differ from Production and
  hide authentication bugs until deployment. A public Development key keeps one code path.
- **Redis / distributed rate limiting:** one instance today; a distributed store is infrastructure this project has not
  justified. The limiter is isolated in `RateLimitingSetup.CreatePartition`; endpoints know only policy names and the
  firewall use case knows nothing about rate limiting.
- **A global limiter before authentication (per IP):** would limit anonymous floods but charge legitimate clients
  behind shared NAT/proxies together and let unauthenticated traffic consume budgets. Unauthenticated requests are cheap
  here (one SHA-256, no body parsing, no analysis) and edge throttling belongs to the gateway/WAF.

## Consequences

- Every existing client of `/api/v1/*` must send `X-API-Key`. The React dev frontend and the smoke script are updated;
  a production browser frontend needs a real identity provider (a browser cannot keep an API key secret).
- Unknown routes answer 401 to anonymous callers (the fallback policy runs before "not found"), which also hides which
  routes exist; authenticated callers still get 404/405.
- Rate-limit state is per process and resets on restart; several instances would each allow the full limit.
- Behind a reverse proxy the anonymous partition key is the proxy's address until forwarded headers are configured for
  known proxies (deliberately not enabled: trusting `X-Forwarded-For` from anyone lets clients choose their partition).

## Future path

- **Identity provider:** add a JWT bearer scheme (OIDC) issuing `permission` claims (or map scopes to them) and a policy
  scheme selecting it by header; `AuthorizationPolicies` and endpoints stay unchanged. Keep API keys for
  service-to-service callers or retire them.
- **Per-client limits / quotas:** add a per-client limit to `ApiClientOptions` and read it in `CreatePartition`.
- **Distributed rate limiting:** replace the partition factory in `CreatePartition` with a limiter backed by a shared
  store (with its own ADR); endpoints, policies and the use case are untouched.
- **Key storage:** move client records from configuration to a secret store or database when clients are managed at
  runtime (keeping hashes only).
