# Architecture overview

AgentShield is a **modular monolith** built with **Clean Architecture**: one deployable API, with boundaries enforced
by project references rather than by network hops. This keeps the prototype simple to run and demo while letting
modules be extracted later if ever needed.

## Layers and dependency direction

```text
                 ┌──────────────────────┐
                 │   AgentShield.Api    │  presentation + composition root
                 └──────────┬───────────┘
        ┌───────────────────┼────────────────────┬───────────────────┐
        ▼                   ▼                    ▼                   ▼
 Infrastructure            AI               Security          (Application)
 (EF Core, cache)   (LLM adapters)   (deterministic rules)
        │                   │                    │
        └───────────────────┴─────────┬──────────┘
                                      ▼
                         AgentShield.Application   use cases, ports, Result/Error, validators
                                      │
                                      ▼
                           AgentShield.Domain       entities, value objects — no dependencies
```

| Rule | Why |
|---|---|
| Domain references nothing | Business concepts stay framework-free and trivially testable |
| Application references only Domain | Use cases depend on abstractions (ports), never on EF Core, LLM SDKs or HTTP |
| Infrastructure, AI, Security reference Application | They are adapters implementing Application ports |
| Outer adapters never reference each other | Keeps modules independently replaceable; Api wires them together |
| Only Api references everything | Single composition root |

These are enforced by project references (see each `.csproj`). Adding a reference that breaks the table requires an ADR.

### Where things go

| Concern | Location |
|---|---|
| Request/response DTOs, FluentValidation validators, use cases | `Application` (per feature folder) |
| Port interfaces: `ICacheService`, `ICorrelationContext`, firewall stages (`IInputNormalizer`, `IThreatDetector`, `IFindingAggregator`, `IRiskEngine`, `IPolicyEngine`, `ISecurityEventSink`); AI analysis (`IAiAssistedAnalysis` stage, `IAiSecurityAnalyzer` provider, request/output contracts, `AiAnalysisErrors`); activity history (`ISecurityActivityStore`) | `Application/Abstractions` |
| Activity history: metadata-only record and its projection from a security event, the recorder (a security-event sink), the query use case | `Application/Activity` |
| `Result`, `Error`, `ErrorType` | `Application/Common/Results` |
| EF Core `DbContext`, entity configurations, migrations, cache | `Infrastructure` |
| LLM provider adapters (`GeminiSecurityAnalyzer`: `IAiSecurityAnalyzer` on a typed `HttpClient`), strict structured-output parser | `AI` |
| AI capacity gate, input-token budget, provider circuit breaker (process-local) | `Infrastructure/AiCapacity` |
| AI analysis guard (disclosure, timeout, validation, failure policy, finding catalogue) | `Security/AiAnalysis` |
| Normalisation, detection rules (plain and obfuscation), finding fusion, risk scoring, policy, redaction | `Security` |
| Controllers, Result→HTTP mapping, Problem Details, middleware, Swagger, health endpoints | `Api` |
| Security vocabulary: `ThreatFinding`/`ThreatSeverity`/`ThreatCategory` (`Domain/Threats`), `RiskAssessment`/`RiskLevel` (`Domain/Risk`), `SecurityDecision`/`PolicyDecision` (`Domain/Policy`), `SecurityEvent`/`SecurityEventId` (`Domain/SecurityEvents`) | `Domain` |
| Security event sink (structured log today, persistence later) | `Infrastructure/SecurityEvents` |
| Activity store (bounded, in memory; a persistent store later, ADR 0019) | `Infrastructure/Activity` |

## Request flow

```text
HTTPS (TLS at Kestrel or the reverse proxy; HSTS outside Development)
  → Routing (implicit, first: every later stage sees the selected endpoint)
  → CorrelationIdMiddleware        (X-Correlation-ID accepted/generated, pushed to log context)
  → Serilog request logging       (one line per request: method, route template, status, duration; never the raw path)
  → Exception handler              (unexpected exceptions → 500 Problem Details)
  → Status code pages              (bodiless 4xx/5xx, e.g. 401/403/404 → Problem Details)
  → SecurityHeadersMiddleware      (nosniff, API CSP, frame denial, no-store on every response)
  → HTTPS redirection / Swagger UI (Development)
  → CORS                           (allow-listed origins; preflight answered here, before credentials)
  → Authentication                 (X-API-Key → client principal with permission claims)
  → ClientLogContextMiddleware     (ClientId on every later log line)
  → Authorization                  (permission policy / fallback "authenticated" → 401 / 403)
  → Rate limiter                   (per-client fixed window → 429 + Retry-After)
  → Controller
      → strict JSON binding        (malformed → 400)
      → FluentValidationActionFilter  (invalid → 422 Problem Details, action never runs)
      → Application use case → Result<T>   (deterministic detection → optional AI → fusion → risk → policy → security event
                                            to every sink: audit log, activity history; or GET activity: one bounded page)
      → ResultActionResultExtensions  (success → envelope; failure → Problem Details)
```

Authentication, authorization, rate limiting, CORS and headers live only in `AgentShield.Api`; the Application use
case, the domain and the Security detectors know nothing about callers or limits
([ADR 0014](../decisions/0014-api-boundary-hardening.md)).

## Security pipeline

```text
Untrusted input → Normalisation → Threat detection → [AI-assisted analysis] → Risk assessment
  → Deterministic policy engine → Security decision → Agent/tool gateway → Authorization → Audit/security event
```

**Implemented (Milestones 1–2):** normalisation → deterministic detection (plain patterns + bounded obfuscation
detection) → finding fusion → risk → policy → security event (logged), behind
`POST /api/v1/firewall/analyze`. Details, scoring rules and limitations: [firewall pipeline](../security/firewall-pipeline.md);
design decisions: [ADR 0010](../decisions/0010-deterministic-firewall-pipeline.md),
[ADR 0011](../decisions/0011-bounded-obfuscation-detection-and-finding-fusion.md).

**Milestone 3 (architecture only):** the AI-assisted analysis boundary between detection and fusion: ports, input and
output contracts, strict validation, 3 s timeout, failure handling by cause, disclosure policy and audit summary
([ai-analysis](../security/ai-analysis.md), [ADR 0012](../decisions/0012-ai-analysis-boundary.md)).

**Milestone 4:** the first provider, Google Gemini (`GeminiSecurityAnalyzer` in `AgentShield.AI`, official
`Google.GenAI` SDK, typed `HttpClient`), enabled by `Ai:Enabled` with the key `Ai:Gemini:ApiKey` from User Secrets; off by
default ([ADR 0013](../decisions/0013-gemini-provider.md)).

**Milestone 5:** the API boundary in front of the pipeline: API key authentication, permission policies (secure by
default), per-client rate limiting, CORS allow-list and security headers
([ADR 0014](../decisions/0014-api-boundary-hardening.md)). Action authorization arrived in Milestone 10 and the tool
gateway that enforces it for one reference tool in Milestone 11 (below); persisted audit is a later milestone.

**Milestone 10:** the agent action authorization boundary, a second decision point next to the firewall: an agent's
proposed tool action is decided Allow / Review / Block from configured agents (bound to their runtime), one required
capability per tool action, risk from declared effects and a deterministic policy — `POST /api/v1/agent/actions/authorize`,
recorded like every security decision. It executes nothing ([agent action authorization](../security/agent-action-authorization.md),
[ADR 0020](../decisions/0020-agent-action-authorization-boundary.md)).

**Milestone 11:** the tool gateway, an enforcement point behind that boundary — `POST /api/v1/agent/tools/execute`. The
agent is its API key's gateway identity; the boundary decides first; on Allow the action's argument policy must accept the
arguments, the execution authority issues a signed, single-use, 30-second grant bound to the call, verifies and consumes
it, and runs the tool once. Only the authority holds a tool (complete mediation); every stage is recorded before the next.
One reference tool, `knowledge.lookup` (an in-memory lookup); every other tool is still decided, not enforced
([tool gateway](../security/tool-gateway.md), [ADR 0021](../decisions/0021-tool-gateway-enforced-execution.md)).

**Milestone 12:** the console's Attack Lab, a thin demonstration layer: 14 fixed scenarios sent unchanged to the firewall
(DETECT → SCORE → POLICY) or the tool gateway (AUTHORIZE → GATEWAY → EXECUTE), each shown as the API answered. The API
gained no demo path, only `GET /api/v1/activity/summary` (counts of the in-memory history, one snapshot) for the
Overview's security operations section ([attack lab](../security/attack-lab.md),
[ADR 0022](../decisions/0022-attack-lab-demonstration-layer.md)).

**Milestone 13:** security closure. A Review at the gateway gets a pending approval bound to the exact call; a person
(`agent:approve`, a separate client outside Development) approves or denies it at `/api/v1/agent/approvals`, and the agent
re-submits the same call, which then runs once through the unchanged gateway. A gateway call can reference its input's
firewall analysis (`inputEventId`), and the server's record of it, not the agent's claim, is weighed. Every recording path
tries every sink under cancellation, and startup failures are reported as themselves (X-05)
([tool gateway](../security/tool-gateway.md) sections 16–18, [ADR 0023](../decisions/0023-human-approval-and-input-event-binding.md)).

**Milestone 6:** bounded AI usage: a per-client capacity gate, an input-token budget and a provider circuit breaker in
front of every provider call; every failure of an expected AI analysis holds the input for review
([ADR 0015](../decisions/0015-ai-capacity-gate.md), [ADR 0016](../decisions/0016-ai-provider-circuit-breaker-and-input-token-budget.md)).
The complete security architecture, with every control in request order, is in
[security-architecture.md](../security/security-architecture.md).

The Application layer orchestrates the pipeline through ports; `Security` provides deterministic implementations,
`AI` provides optional analysis signals, and the **policy engine owns the final decision**. See
[security principles](../security/principles.md).

## Frontend

`frontend/agentshield-web` uses a feature-oriented layout:

```text
src/
  app/        router, providers (TanStack Query), layouts
  features/   one folder per feature (api/, hooks/, components/, index.ts public surface)
  shared/     components, constants (and hooks/types/utils as they appear)
  services/api  the only place that talks HTTP
```

Component → feature hook (TanStack Query) → feature API function → central `apiClient` → backend. The client
centralises base URL, JSON, `X-Correlation-ID`, auth header injection, timeout/cancellation and Problem Details
normalisation into a single `ApiError`. See [API conventions](../api/conventions.md#frontend-client).
