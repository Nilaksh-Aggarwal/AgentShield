# Architecture decision records

Short, immutable records of significant decisions. To change a decision, add a new ADR that supersedes the old one.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-modular-monolith-clean-architecture.md) | Modular monolith with Clean Architecture | Accepted |
| [0002](0002-build-quality-gates.md) | Analyzers, warnings as errors, central package management | Accepted |
| [0003](0003-result-pattern-and-http-mapping.md) | Result pattern with centralised HTTP mapping and Problem Details | Accepted |
| [0004](0004-swashbuckle-openapi.md) | Swashbuckle for OpenAPI/Swagger UI | Accepted |
| [0005](0005-optional-persistence-until-first-entity.md) | Persistence activates only when configured | Accepted |
| [0006](0006-opt-in-convention-registration.md) | Opt-in Scrutor registration via lifetime markers | Accepted; registration strategy superseded by 0008 |
| [0007](0007-frontend-state-and-forms.md) | TanStack Query for server state; forms library deferred | Accepted |
| [0008](0008-convention-registration-keeps-every-implementation.md) | Convention registration keeps every implementation; explicit wins single resolution | Accepted |
| [0009](0009-strict-json-input.md) | Strict JSON input (no duplicates, unknown members, lenient enums) | Accepted |
| [0010](0010-deterministic-firewall-pipeline.md) | Deterministic firewall pipeline: one port per stage, policy decides, fail closed | Accepted |
| [0011](0011-bounded-obfuscation-detection-and-finding-fusion.md) | Bounded obfuscation detection (decoded, unmasked and hidden-character views, fail-safe limits) and finding fusion as its own stage | Accepted (amended 2026-09-30) |
| [0012](0012-ai-analysis-boundary.md) | AI-assisted analysis boundary: findings only, validated centrally, failures handled by cause | Accepted; provider-failure fallback superseded by 0016 |
| [0013](0013-gemini-provider.md) | First AI provider: Gemini via the official Google.GenAI SDK, typed client, off by default, key `Ai:Gemini:ApiKey` from User Secrets (amended 2026-10-01: no redirects, no provider text in exceptions) | Accepted; off-by-default amended by 0024 |
| [0014](0014-api-boundary-hardening.md) | API boundary hardening: API key authentication, permission policies (secure by default), in-memory per-client rate limiting, CORS allow-list, security headers | Accepted |
| [0015](0015-ai-capacity-gate.md) | AI capacity gate: AgentShield's own AI budget below the provider quota, per-client shares, Review on exhaustion, deterministic Block skips AI | Accepted |
| [0016](0016-ai-provider-circuit-breaker-and-input-token-budget.md) | AI provider circuit breaker (one probe, no retries), conservative local input-token budget, and Review instead of deterministic-only on provider unavailability (supersedes that part of 0012) | Accepted |
| [0017](0017-ai-evaluation-tooling-project.md) | AI evaluation tooling project `tests/AgentShield.Evaluation`: tested, resumable, capped real-Gemini runner; never referenced by `src/`, never deployed | Accepted |
| [0018](0018-assurance-tooling.md) | Assurance tooling: Stryker.NET mutation testing on demand (three scopes), Vitest frontend tests, browser checks committed as dependency-free scripts (not Playwright) | Accepted |
| [0019](0019-security-activity-history.md) | Security activity history: metadata-only read model of security events, recorded from the final decision through every sink (fail closed), bounded in-memory store behind a port, `GET /api/v1/activity` behind `activity:read` | Accepted |
| [0021](0021-tool-gateway-enforced-execution.md) | Tool gateway: enforced execution behind the unchanged authorization boundary, agent identity from the credential (`GatewayClient`), per-tool argument policy, HMAC-signed single-use 30 s execution grants issued only on Allow, complete mediation (only the execution authority holds a tool), every stage recorded before the next, `POST /api/v1/agent/tools/execute` behind `tool:execute`; one in-memory reference tool | Accepted |
| [0020](0020-agent-action-authorization-boundary.md) | Agent action authorization boundary: decide-only (no execution), configured agents bound to API clients, capability per tool action, risk from declared effects, ordered deterministic policy (Critical denied, input decision only tightens), recorded as metadata, `POST /api/v1/agent/actions/authorize` behind `agent:authorize` | Accepted |
| [0022](0022-attack-lab-demonstration-layer.md) | Attack Lab: a console-only demonstration layer over the real firewall and tool gateway (14 deterministic scenarios, results always the API's, one deliberate contract violation for the replay), counts-only `GET /api/v1/activity/summary`, metadata-only export, no CORS on the Vite servers (H-08), the gateway's failure entry on cancellation (D-21) | Accepted |
| [0023](0023-human-approval-and-input-event-binding.md) | Human approval for held tool calls (pending approval bound to the exact call, decided by a separate `agent:approve` client, recorded before it takes effect, used once through the same gateway), binding a tool call to the server's record of its input analysis (`inputEventId`, strictest decision wins), every sink tried under cancellation, and the X-05 startup fix | Accepted |
| [0024](0024-ai-analysis-on-by-default.md) | AI-assisted analysis on by default (`Ai:Enabled = true`); no key means no start; running without AI only explicitly (`Ai__Enabled=false`, `http-deterministic` profile); tests and tooling stay offline; decision boundary unchanged (amends 0013) | Accepted |
| [0025](0025-reliability-rules-and-held-out-evaluation.md) | Reliability rules IO-004..IO-010, RM-004..RM-007, SE-003..SE-005 in the existing categories, developed on a tuning split and measured once on a held-out split written before any rule change; stored results re-checked by a test | Accepted |
