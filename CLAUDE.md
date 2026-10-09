# CLAUDE.md — AgentShield engineering rules

Read this file before changing anything. It is the contract for every session. Details and rationale live in
`docs/` (architecture, API conventions, security, ADRs). Current status lives in `docs/PROGRESS.md`.

AgentShield is an AI security firewall prototype (ET AI Hackathon: Agentic Edition, presented by Accenture).
Stack: .NET 10 / ASP.NET Core 10 (C#), PostgreSQL + EF Core, React 19 + TypeScript + Vite 8.

---

## 0. Workflow rules (mandatory in every session, set by the project owner on 2026-10-09)

**Rule 1: never commit or push without explicit approval.**
- Never run `git commit`, `git push`, `git reset`, `git rebase`, `git cherry-pick` or any history-rewriting command
  without the owner's explicit approval **for that specific operation**.
- Never amend or delete existing commits unless explicitly authorized.
- Never run `git init` or create another GitHub repository unless explicitly requested.
- Being asked to implement, fix, test, review, save or finish something is **not** approval to commit or push.
- Inspecting Git status, branches, remotes, diffs and history is always allowed.
- Before asking for commit approval, report the exact changed files, the staged diff, the test results and any security
  concerns.
- Commit approval and push approval are separate.
- Before pushing, show the destination remote, the branch and the files or commits being published, then wait for
  explicit approval.
- Never discard, reset or overwrite the owner's uncommitted work. If a destructive action seems necessary, explain why
  and wait.

**Rule 2: Gemini AI-assisted analysis is on by default** ([ADR 0024](docs/decisions/0024-ai-analysis-on-by-default.md)).
- `Ai:Enabled` is `true` in `appsettings.json` and `appsettings.Development.json`; Gemini stays the provider; use only the
  existing model configuration (`Ai:Model`) and never invent model names or API settings.
- The key stays outside source control: User Secrets locally, `Ai__Gemini__ApiKey` or a secret store when deployed.
  Never put a real key in `appsettings*.json`, `launchSettings.json`, source, tests, documentation or Git history.
- **Missing key:** the API refuses to start with a clear message. Running without AI is explicit only: `Ai__Enabled=false`
  or the `http-deterministic` launch profile. Never silently disable AI to make a demo or test pass; when AI is off or
  unavailable, say so and keep deterministic-only results apart from AI-enabled ones.
- Gemini supplies findings only. The deterministic risk and policy engines remain the final authority for Allow / Review /
  Block; AI never authorizes a tool action; fail-closed handling of inconclusive analysis and failures is preserved.
- Normal tests use fakes or scripted analyzers and never need a live key. Real-provider runs are opt-in and explicitly
  identified. Report for every AI-assisted evaluation whether Gemini was really called, with which model, and whether
  a fake analyzer stood in.
- Never change production or deployed secrets as part of a task; document environment-specific overrides instead.

**Rule 3: keep this file current.**
- These workflow and AI rules are project-wide requirements for every future session.
- When an existing configuration or instruction conflicts with them, name the conflict and propose the smallest safe
  correction.
- Show the owner the exact diff of any change to this file, and never commit or push it without approval.
- This file is guidance, not an enforced boundary. Deterministic safeguards (Claude Code permissions or hooks) are proposed
  separately for the owner's approval.

---

## 1. Architecture rules

Modular monolith, Clean Architecture, dependency inversion. Projects (do not rename, merge or add projects without an ADR):

| Project | Role | May reference |
|---|---|---|
| `AgentShield.Domain` | Entities, value objects, domain rules | **nothing** |
| `AgentShield.Application` | Use cases, DTOs, validators, abstractions (ports), `Result`/`Error` | Domain |
| `AgentShield.Infrastructure` | EF Core/PostgreSQL, caching, other I/O adapters | Application |
| `AgentShield.AI` | LLM/AI-assisted analysis adapters | Application |
| `AgentShield.Security` | Deterministic normalisation, detection, risk, policy, redaction | Application |
| `AgentShield.Api` | HTTP presentation + composition root | Application, Infrastructure, AI, Security |

Test and tooling projects live under `tests/`: the four test projects and `AgentShield.Evaluation` (ADR 0017), the manual
AI evaluation runner. It may reference Api (in-memory host) only; nothing in `src/` may reference it.

Hard dependency rules:

- Domain → nothing. No ASP.NET Core, EF Core, Serilog, provider SDKs in Domain.
- Application → Domain only. **Never** Infrastructure, AI, Security or Api.
- Infrastructure / AI / Security → Application (implement its abstractions). They never reference each other or Api.
- Only Api composes everything. No dependency cycles.
- If Application needs something an outer layer provides, define an interface in `Application/Abstractions` and implement it outside.
- Only create an abstraction for a genuine boundary (I/O, external system, swappable policy). No abstraction for its own sake, no generic repository.

## 2. Security principles (non-negotiable)

- The LLM is **never** the final security authority. AI output is one input to deterministic risk evaluation and policy.
- Target pipeline: input → normalisation → deterministic detection → AI-assisted analysis (optional) → risk → deterministic policy → decision → authorization → audit.
- A security decision (ALLOW / BLOCK / SANITIZE / REVIEW) is a domain result, **not** an HTTP status. A successful analysis that decides BLOCK returns **200** with the decision in `data`.
- Treat all request data, headers, LLM output and tool results as untrusted.
- `CorrelationId` (request trace) and `SecurityEventId` (identity of a security event) are different things; never conflate them.
- Detection rules (spec: `docs/security/firewall-pipeline.md`, ADRs 0010–0011):
  - Detectors only report findings. Every detector must be deterministic, bounded (linear time, `NonBacktracking` regex
    with timeout) and must never put input or decoded content into a finding.
  - Duplicates are fused by `IFindingAggregator` (key: category + code) before risk. Order: severity → category → code.
    Do not dedupe or sort in detectors, risk or policy.
  - Encoded-looking data is not malicious. A decoder never raises a finding; only a rule that matches *after*
    decoding/unmasking (and not before) does. Decoding is bounded (`ObfuscationLimits`): never recursive, never
    truncating. Over a limit → `Obfuscation.UninspectableContent` (Review), not a silent skip.
  - Normalisation stays non-destructive for legitimate text; lossy folding (look-alikes, accents, spacing, leetspeak)
    belongs only in the obfuscation detector's views. Invalid UTF-16 and U+FFFE (rejected by `string.Normalize`, D-18)
    become U+FFFD; nothing else is replaced.
  - Detector identities, rule IDs and transformation chains are audit data: logged, never returned by the API.
  - Reliability sets (`tests/Evaluation/reliability`, ADR 0025): develop rules only against the tuning split; the
    held-out split is pinned and never edited or tuned against, and labels never change to fit results. After a rule
    change, re-run `reliability --label final --split all` and store the results (`ReliabilitySetTests` fails on stale
    results), and report deterministic and AI-assisted results separately.
- AI-assisted analysis rules (spec: `docs/security/ai-analysis.md`, ADR 0012):
  - Provider adapters implement `IAiSecurityAnalyzer` in `AgentShield.AI` and return the **raw** answer
    (`AiAnalysisOutput`, via `AiStructuredOutputParser`) or an `AiAnalysisErrors` failure. They never build
    `ThreatFinding`s, never retry, never log content/prompts/answers. Validation, timeout and failure handling happen
    only in `AiAssistedAnalysis` (Security); do not bypass or duplicate them. `EstimateInputTokens` is a local,
    conservative upper bound over everything the adapter sends; never a provider token-count request.
  - AI output has no decision field and is validated all or nothing. AI codes come only from `AiFindingCatalog` and
    never equal a detector code; model-written text never reaches a finding, response or log.
  - AI only adds findings; it goes through the existing aggregator, risk and policy. No AI-specific risk engine, no
    confidence weighting without a milestone.
  - Every failure of an expected AI analysis → `InconclusiveAnalysis.AiAnalysisIncomplete` (Review), provider
    availability failures included (ADR 0016; nothing falls back to deterministic-only); exceptions → 500. Change
    `AiFailurePolicy` only with its rationale.
  - Content leaves the process only through `IAiDisclosurePolicy` (normalised, secrets masked, never truncated).
  - AI is enabled by registering a provider, which `AddAI` does only when `Ai:Enabled` is true (`true` in both
    appsettings files since ADR 0024; without a key the API refuses to start; run without AI only explicitly with
    `Ai__Enabled=false` or the `http-deterministic` profile); the test double stays in the test projects. No AI result caching.
  - Gemini (ADR 0013, `ai-analysis.md` section 15): official `Google.GenAI` SDK through the typed `HttpClient`. Keep its
    hardening: pinned endpoint, `Attempts = 1`, typed-client timeout (1–3 s, never above the stage's 3 s), 256 KiB
    response cap, non-thought text only, provider exception messages never used or logged (an unmapped exception leaves the
    adapter as `GeminiAdapterFaultException`, without its message), redirects never followed, HTTP status mapped by cause.
  - The API key is `Ai:Gemini:ApiKey`, set only in User Secrets (Development) or `Ai__Gemini__ApiKey` (environment);
    committed appsettings keep the empty placeholder. Test factories force `Ai:Enabled=false` and a blank key. Never in
    the frontend, `VITE_*`, logs, responses or Swagger. Automated tests never call Google; the real-API smoke test is the manual
    `scripts/gemini-smoke.ps1` (never a skipped test). Free tier: text only, no grounding/tools, demo content only (Google may use it).
  - AI quality evaluation (`ai-analysis.md` section 18, ADR 0017): labelled synthetic set in `tests/Evaluation` (labels
    are never produced or adjusted from model output, changed only deliberately via the pinned fingerprint; never a real
    secret). Real-Gemini runs only through `tests/AgentShield.Evaluation` (`plan`, then `final`) with the AI Studio limits
    stated on the command line; hard cap, pacing, one attempt per fixture, stop at the first 429, the second 5xx or a
    timeout; completed fixtures are never re-sent. Results (`tests/Evaluation/results`) hold fixture IDs, codes and
    numbers only. Never quote AI accuracy beyond the completed analyses the report states.
  - AI capacity (ADR 0015, `ai-analysis.md` section 16): every provider call goes through `IAiCapacityGate` in
    `AiAssistedAnalysis`; never call a provider around it. A refusal is `CapacityExceeded` → Review (never deterministic
    Allow); a deterministic Block skips the AI (`NotNeeded`), decided by the real risk/policy engines, not a copied
    threshold. Budgets (`Ai:Capacity`) are AgentShield's own, below the provider quota; never hard-code provider limits.
    No waiting queue; release the admission however the call ends. Gate state is keyed by configured client IDs only
    (`ICallerContext`, `IApiClientDirectory`), never keys. Metric tags stay bounded. Observability never changes
    accounting: record metrics and logs after the state change, and give a slot back if they throw. Only a deterministic
    Block may skip the AI; the stage treats any other "not needed" as a refusal (Review).
  - Circuit breaker and input tokens (ADR 0016, `ai-analysis.md` section 17): stage order Block skip → disclosure →
    token estimate → `IAiCircuitBreaker` → capacity → one call → report the normalised outcome. Only
    `AiProviderAvailability.IsAvailabilityFailure` counts (429/5xx/network/timeout), never a rejected request (400, and
    401/403/404 key/permission/model faults) or a bad answer; do not classify provider status codes anywhere but the adapter. One circuit per process, one probe at a
    time, no retries, no queue. Token reservations are local estimates, never below the byte floor, not refunded.
    Capacity and circuit state are process-local; canary, degraded mode and distributed state are not built.

- Security activity history (ADR 0019, invariants 39–43; agent actions since ADR 0020, invariant 51; tool calls since
  ADR 0021, invariant 69):
  - A read model filled only by `SecurityActivityRecorder` (an `ISecurityEventSink`) from the finished `SecurityEvent`,
    by `AgentActionActivityRecorder` (an `IAgentActionEventSink`) from the finished `AgentActionEvent`, and by
    `ToolGatewayActivityRecorder` (an `IToolGatewayEventSink`) from a tool gateway request's last `ToolGatewayEvent` only.
    It never decides, recomputes risk or changes a decision; it copies them.
  - `SecurityActivityRecord` is metadata only: IDs, time, kind, decision, risk (level; score only for input analyses),
    finding code/category/severity, coarse AI status (every failure is `Incomplete`), for agent actions the
    recognised agent/tool/action/capability and reason, and for tool calls the outcome, executed flag and execution ID.
    Never input, decoded content, secrets, prompts, provider output or errors, rule IDs, detectors, descriptions, AI
    failure reasons, tool arguments or results, argument or grant rejection codes, or made-up names. A new field is a deliberate privacy
    decision (a test pins the field set); responses map field by field.
  - The analyze use case gives the event to every sink; a sink failure fails the analysis closed (500, no decision)
    after the other sinks recorded. Never swallow it.
  - The store is in memory and bounded (1,000), per process, not durable and not the audit trail: never claim audit
    durability for it. Persistence needs its own ADR.
  - `GET /api/v1/activity` needs `activity:read` (an operator permission; firewall clients do not get it). Page size
    ≤ 100; query values are bound as text, accepted as exact names and never echoed in errors. `GET /api/v1/activity/summary`
    (same permission) returns counts only, from one read of the store; never IDs, names or content.
- Agent action authorization (spec: `docs/security/agent-action-authorization.md`, ADR 0020, invariants 44–56):
  - The agent proposes; `IAgentActionAuthorizer` (Security) decides Allow / Review / Block. It never executes; tools run
    only in the tool gateway (below). Only Allow (or, at the gateway, a Review a person approved) permits execution; for tools outside the gateway enforcement is the
    caller's. Never describe the boundary, or any tool not behind the gateway, as enforced.
  - Facts come only from trusted data: agents, grants and bound clients from `AgentAuthorization:Agents` (validated at
    startup, immutable), tool actions from `ReferenceToolCatalog` (code, pinned by tests). The caller comes from
    authentication (`ICallerContext`), never from the body. The request has no arguments, decision, risk, grants or
    reasoning field (strict JSON → 400); do not add one without an ADR.
  - Names are exact lower-case ASCII (`AgentIdentifiers`); never normalise or compare them case-insensitively.
    Capabilities are exact (no wildcards); the checked capability is the catalogue's, held only if the profile holds it.
  - Risk is classified only from declared `ActionEffects` (worst effect wins; no effect is invalid; unknown → Critical);
    never from names, never by AI. Policy order lives only in `AgentActionPolicy`: every Block rule before every Review
    rule; Critical → Block for every agent; the reported input decision only tightens. A reason has exactly one decision.
  - Recording follows the security-event contract (every sink, then fail closed). Only recognised names are recorded;
    made-up names are `null`/`(unknown)`. No activity kind per decision. Production configures no agent.
- Tool gateway (spec: `docs/security/tool-gateway.md`, ADR 0021, invariants 57–70):
  - Complete mediation: only `ExecutionGrantAuthority` (Security) holds `IToolExecutor`s, only `ToolGateway`
    (Application) holds `IToolExecutionAuthority`, only `AgentToolsController` holds `IToolGateway` (a reflection test
    pins it). Never inject an executor or the authority anywhere else, and never add another endpoint that runs a tool.
  - Order: agent from the key → verified input reference → the M10 boundary, unchanged (its Block ends there; its Review
    too, unless the request presents an approval of exactly this call, used once) → an executable tool → the action's
    argument policy → a grant → the authority runs the tool once. The gateway's own checks only turn an Allow into
    a Block; there is no second policy engine. Each `ToolExecutionOutcome` has exactly one decision.
  - The agent comes only from `IAgentDirectory.FindByGatewayClient` (exact match, trusted only): every `tool:execute`
    client is exactly one agent's `GatewayClient`, which is one of its `Clients` (startup validation). The request has no
    agent, decision, risk, grant, execution-authorization or credential field (strict JSON → 400); do not add one without
    an ADR.
  - Tools decide nothing and never see raw JSON: they receive the typed `ToolArguments` their argument policy built (one
    sealed subtype per action, its schema enforced in the constructor). Small explicit schemas, no policy language.
  - Grants: HMAC-SHA256 over every field under a per-process random key (never configured, logged, returned or exported),
    single use (atomic ledger, bounded), 30 s, bound to the call the gateway builds from its own request; `Issue` asks the
    boundary again. A grant never leaves the process (no request or response field carries one).
  - Every stage goes to every `IToolGatewayEventSink` before the next (every sink tried, then fail closed: 500, no decision,
    no result); `ToolGatewayEvent` is built only through its transitions. Never log or record arguments, results or
    signatures; argument and grant rejection codes go to the audit log only, never to responses or activity.
  - One executable tool: `knowledge.lookup` (in-memory dataset, no I/O). A new executable tool needs an executor, an
    argument policy and a catalogue entry with declared effects; no tool with real I/O (network, files, database, email,
    payments, shell, MCP, AI) without an ADR. Production configures no gateway client.
- Attack Lab (spec: `docs/security/attack-lab.md`, ADR 0022, invariants 71–73):
  - A console-only demonstration layer: static scenarios sent unchanged to the firewall or the tool gateway. No demo
    endpoint, flag or code path in the API, and no security logic in the console (it never decides, scores, authorises
    or runs anything).
  - Results are the API's: never show a scenario's intent in place of the result; unknown values are never echoed; a
    tool counts as run only when the decision is Allow, `executed` is true and the outcome is `Executed`.
  - The only deliberate contract violation is the replay scenario's `executionId`, which must stay a 400. Never add a
    request field, a detector or a rule just to make a scenario pass; a scenario the rules miss stays a labelled known
    miss. Scenarios work with AI off; an AI-assisted scenario must be labelled as one.
  - Security operations counts come only from the summary endpoint and are labelled as this process's in-memory history:
    no period, trend, percentage or number the API did not return; nothing while loading or after a failure. The export
    is a metadata-only allowlist. The Vite dev and preview servers keep `cors: false` (H-08).
- Human approval and input binding (spec: `docs/security/tool-gateway.md` sections 16–18, ADR 0023, invariants 74–81):
  - Review never runs by itself. Only the gateway creates an approval (`ToolApproval`), for a Review it holds when a tool
    here runs the action, bound to agent, client, tool, action, capability, SHA-256 of the arguments as sent and the input
    event. A held call runs only when re-submitted with an `approvalId` that `TryUse` accepts (Approved, unexpired,
    unused, binding equal), and `ExecutionGrantAuthority` re-checks that this request used it. A Block is never lifted.
    No approval field but `approvalId`, no "approved" flag, no second execution path.
  - Deciding needs `agent:approve` (`AgentApprove`; no body; the decider comes from authentication): begin → record
    (`ToolApprovalEvent`, every `IToolApprovalEventSink`) → complete; a failed or cancelled recording withdraws it. Outside
    Development `agent:approve` never combines with `tool:execute` or `agent:authorize` (startup fails). Approvals are in
    memory, per process (`ToolApprovals:LifetimeSeconds`, default 600); durable or shared approvals need an ADR.
  - `inputEventId` references a firewall analysis recorded by `InputSecurityContextRecorder` (event, trace, client,
    decision; never content). Verified (same client, same trace, ≤ 10 min) or `InputContextRejected`; the strictest of the
    record, the approval's and the caller's decision wins. Never let a claim replace the record. The reference is
    optional (a stated limitation); never describe input binding as enforced for calls that omit it.
  - Every recording path uses `EventSinks.PublishToEveryAsync` (every sink, cancellation included, then fail closed).
    Input-context and approval rejection codes go to the audit log only, never to responses or activity.
- API boundary rules (spec: `docs/api/conventions.md`, ADR 0014):
  - Every endpoint requires an authenticated client (fallback policy). `AllowAnonymous` only for health probes or with
    a documented reason. Authorization = named permission policies (`AuthorizationPolicies`, `Permissions`) declared
    with `[Authorize(Policy = ...)]`; never role/permission checks in controllers, Application, domain or detectors.
  - API keys: `X-API-Key`, only SHA-256 hashes in configuration (`Authentication:Clients:{id}`), constant-time
    comparison, one identical 401 for every failure, never logged or echoed. The public Development key works only in
    Development (startup fails elsewhere); never add a bypass or an "anonymous in dev" principal.
  - Rate limiting: built-in limiter, per-client partitions, runs after authorization; controllers inherit `Standard`
    from `ApiControllerBase` (agent authorization, the tool gateway, approvals and activity included), the firewall uses `Firewall`, `/health/live` is never limited. No Redis without an ADR.
    `RateLimiting:Enabled=false` only in Development. 429 = Problem Details + `Retry-After`.
  - CORS origins only from `Cors:AllowedOrigins` (no `*`, no credentials, https outside Development). Security headers
    come from `SecurityHeadersMiddleware`; do not add a frontend CSP to the API.

## 3. Coding standards

- `Directory.Build.props` enables nullable, latest analyzers (Recommended), code-style enforcement and **warnings as errors**. Fix warnings; do not suppress to make the build pass. If a rule must be disabled, do it narrowly (`.editorconfig` or `[SuppressMessage]`) **with a justification**.
- File-scoped namespaces, `_camelCase` private fields, PascalCase constants/static readonly, braces always.
- Async all the way for I/O. Pass `CancellationToken` through every async call. Never `.Result`, `.Wait()`, or `Task.Run` to fake async.
- Constructor injection only. No service locator in application code (framework glue such as MVC filters may resolve by runtime type — document why).
- Options pattern for configuration (`AddOptions<T>().Bind(...).Validate(...).ValidateOnStart()`); no `configuration["key"]` in application code.
- Package versions live only in `Directory.Packages.props` (Central Package Management).

## 4. Results, errors and HTTP

- Expected failures → `Result` / `Result<T>` with `Error(Code, Message, Type, Metadata)`. Unexpected failures → exceptions, handled centrally. Do not throw for control flow.
- `Result` and `Error` contain **no HTTP concepts**. HTTP mapping lives only in `AgentShield.Api/Http/Results`.
- `Error.Code` is stable and machine-readable (`Area.Reason`, e.g. `Firewall.InputTooLarge`). `Error.Message` is client-safe (no secrets, stack traces, SQL, hostnames).
- `ErrorType` → status: Validation 422, BusinessRule 422, NotFound 404, Conflict 409, Unauthorized 401, Forbidden 403, ExternalDependency 502, Unexpected 500.
- Framework statuses: 401 (no valid API key), 403 (missing permission), 429 (rate limited, `Retry-After`) — all
  Problem Details with `errorCode` and `correlationId`.

## 5. API conventions

- Routes: `/api/v1/...` via `ApiRoutes.V1`. Controllers derive from `ApiControllerBase`.
- Controllers are thin: bind → one Application use case → `result.ToOkResult()` / `ToCreatedResult(...)` / `ToAcceptedResult()` / `ToNoContentResult()`. No business rules, EF queries, AI calls or security logic in controllers. No try/catch in controllers.
- Success bodies: `{ "data": ..., "meta": { "correlationId", "timestamp" } }`. No `success` flag. 204 has no body.
- Errors: RFC 9457 Problem Details (`application/problem+json`) with `correlationId`, `timestamp`, `errorCode` (+ `errors` for validation).
- 400 = malformed/unparseable request; 422 = well-formed but invalid. Validators (FluentValidation) live in Application next to the request DTO and run automatically before the action.
- Do **not** put `[Produces]` on controllers (it rewrites problem responses to `application/json`). Document with `[ProducesResponseType]`.
- JSON: camelCase, enums as exact names, strict numbers — configured once in `JsonConventions`. Request bodies are read
  strictly (ADR 0009): duplicate, unknown or differently cased properties → 400. Request DTO members the client may omit
  are nullable and their presence is a validator rule (422); no `[JsonRequired]`/`required` on request DTOs.

## 6. Logging conventions

- Log through `ILogger<T>` with message templates: `logger.LogInformation("Decision {Decision} in {DurationMs} ms", decision, ms)`. Never string interpolation/concatenation.
- **Never log**: passwords, API keys, tokens/JWTs, connection strings, secrets, request/response bodies, prompts containing user data, unnecessary PII, raw request paths or query strings (log the route template, `EndpointNames`). Log exceptions raised while handling a request as text (`ExceptionDetail`), not as exception objects, so the redactor sees them. The redaction enricher is defence in depth, not a licence.
- Security events are the audit trail: outside Development the API refuses to start if the log level hides them; do not
  remove that check or log them below Information.
- Every log line in a request carries `CorrelationId` automatically.

## 7. Dependency injection

- Each layer exposes one entry point: `AddApplication()`, `AddInfrastructure(configuration)`, `AddAI(configuration)`, `AddSecurity()`, `AddApiPresentation(configuration)`.
- Convention registration (Scrutor): a class opts in by implementing `IScopedService`, `ITransientService` or `ISingletonService`; it is registered against its other interfaces. Every implementation of a shared interface is registered (all resolve via `IEnumerable<T>`); the same implementation is never registered twice (ADR 0008). Validators are registered automatically.
- Register **explicitly** anything that needs configuration, a special lifetime, keyed registration, `HttpClient`, `DbContext` or framework setup. An explicit registration wins single-service resolution over the convention, before or after the scan; to exclude a marked class from `IEnumerable<T>` too, remove its marker.

## 8. External calls and resilience

- HTTP only via `IHttpClientFactory` typed clients registered in the owning layer, with explicit timeouts and cancellation.
- Retries only for idempotent operations. Never automatically retry POSTs, tool executions or anything with side effects.

## 9. Testing rules

- `UnitTests`: Domain, Application, pure logic. `SecurityTests`: Security project (rules, normalisation, detection, adversarial inputs). `ApiTests`: HTTP contracts via `WebApplicationFactory` (status codes, Problem Details, validation, routing). `IntegrationTests`: full composition, health, infrastructure boundaries, logging pipeline.
- Tests must verify behaviour — no placeholder or coverage-only tests. Name tests `Method_Scenario_Expectation`.
- Security features ship with adversarial test cases.

## 10. Package rules

Before adding a package: (1) check whether .NET already provides it, (2) check current official docs, (3) verify .NET 10 / React 19 compatibility, (4) prefer maintained packages, (5) add only what is needed now, (6) record why it exists (comment in `Directory.Packages.props` or `docs/architecture/dependencies.md`). NuGet restores only from nuget.org (`nuget.config`). Vulnerability warnings (NU1901–NU1904) must be triaged, not ignored.

## 11. Do not

- Do not introduce Redis, Kafka, RabbitMQ, Kubernetes, microservices, event sourcing, a CQRS/mediator framework, generic repositories or distributed infrastructure without an ADR.
- Do not add Redux; server state = TanStack Query, local state = React state/context.
- Do not call `fetch` outside `frontend/agentshield-web/src/services/api` (ESLint enforces this).
- Do not expose stack traces, exception messages, connection strings or secrets in any response, in any environment.
- Do not commit secrets (use user-secrets / environment variables; `ConnectionStrings__AgentShield`, `Ai:Gemini:ApiKey`,
  production API key hashes `Authentication__Clients__*`). The Development API key is public by design and is the only
  key allowed in a committed file.
- Do not create speculative entities, tables or empty folders.
- Do not `git reset --hard`, `git clean` or discard user changes.

## 12. Verification before claiming done

Run and report real results:

```bash
dotnet restore AgentShield.slnx
dotnet build AgentShield.slnx
dotnet test AgentShield.slnx

cd frontend/agentshield-web
npm install
npm run lint
npm test
npm run build
```

When the UI changed, also run the browser checks (`npm run test:e2e`, after `dotnet build` and `npm run build`). Mutation
testing (`tests/mutation/`, Stryker.NET) is run on demand for changes to the security core.

Never claim success for a command you did not run. If something fails: identify the actual failure, fix, re-run, report honestly. Update `docs/PROGRESS.md` at the end of each milestone.
