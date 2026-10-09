# 0015 — AI capacity gate: AgentShield's own AI budget, per-client shares, Review on exhaustion, Block skips AI

- **Status:** Accepted — 2026-09-30 (Milestone 6, step 1)
- **Extends:** [0012](0012-ai-analysis-boundary.md) (AI analysis boundary: failure table) and
  [0014](0014-api-boundary-hardening.md) (authenticated client identity, in-process limits). Nothing is superseded.
- **Extended by:** [0016](0016-ai-provider-circuit-breaker-and-input-token-budget.md) (input-token budget in the same
  gate, `IsCallNeeded`, circuit breaker before admission).

## Context

AI analysis uses the Gemini API free tier. Google's limits are per Google project (observed for this project on
2026-09-30: 15 requests per minute, 250,000 tokens per minute, 500 requests per day) and are shared by everything using
that project. Until now AgentShield sent one AI request per analysis with no budget of its own: one busy or hostile API
client could spend the whole quota. The API rate limiter (ADR 0014, 60 analyses per minute per client) is far above the
provider quota and not shared between clients.

An evaluation showed that the deterministic rules miss many paraphrased and non-English attacks that Gemini detects.
The AI signal is therefore a security control: if running out of AI capacity silently fell back to the deterministic
decision, an attacker could exhaust the capacity first and then send exactly the attacks only the AI detects, and they
would be allowed.

## Decision

1. **A provider-agnostic admission port, `IAiCapacityGate` (Application), asked by the AI stage before every provider
   call.** It answers `Admitted`, `NotNeeded`, `CapacityExceeded` or `ConcurrencyExceeded`, never waits (no queue) and
   consumes nothing unless it admits. An admission (`AiAdmission`, disposable) holds a concurrency slot until the call
   ends. The gate knows client IDs and the deterministic decision, nothing about providers, models or content.
2. **Refusal holds the input for review.** A refusal becomes the existing `InconclusiveAnalysis.AiAnalysisIncomplete`
   finding (Medium) via the new status `AiAnalysisStatus.CapacityExceeded` (`AiFailurePolicy`: Review). Deterministic
   Allow → Review, Review → Review, Block stays Block. The client sees the same generic finding as for any AI failure;
   the reason is logged, not returned. Provider-side failures (503, 429, network) are unchanged (deterministic only)
   until the circuit-breaker step.
3. **Deterministic Blocks skip the AI** (`Ai:Capacity:SkipWhenDeterministicBlock`, on by default): the stage computes
   the deterministic decision with the real `IRiskEngine` and `IPolicyEngine` (no second threshold) and passes it to the
   gate, which answers `NotNeeded` for a Block (new status `AiAnalysisStatus.NotNeeded`). Safe because AI findings only
   add and the risk level is the highest severity: no AI answer can lower or change a Block.
4. **In-memory implementation (`InMemoryAiCapacityGate`, Infrastructure):** rolling sliding-log windows of 60 s and
   24 h on the monotonic `TimeProvider` clock (never calendar resets); global limits per minute and per day; per-client
   guaranteed and maximum shares in both windows, with the invariant `used + Σ unused guarantees ≤ global limit`, so no
   client can take another client's guarantee even before that client's first call; global and per-client concurrency
   limits. State is keyed by the configured analysis client IDs only (unknown IDs refused, never stored).
5. **Configuration `Ai:Capacity` (`AiCapacityOptions`)**, no defaults in code, validated at startup only when
   `Ai:Enabled` is true: positive limits, guarantee ≤ maximum ≤ global, day guarantee ≥ minute guarantee, client
   concurrency ≤ global, `WhenExceeded = Review` (the only value), and `analysis clients × guarantee ≤ global` for both
   windows. Committed values (both appsettings files): 10/min, 400/day, 4 concurrent; per client 2–4/min, 80–160/day,
   2 concurrent. These are AgentShield safety budgets deliberately below the observed provider quota; the provider's
   limits are not in code or configuration.
6. **Two small Application ports for identity**, implemented in Api: `ICallerContext` (authenticated client ID, never
   the key) and `IApiClientDirectory` (IDs of configured clients holding `firewall:analyze`, the population that shares
   the budget). No HTTP types reach Application, Security or Infrastructure.
7. **Observability with built-in APIs only:** counter `agentshield.ai.admissions` (meter `AgentShield.AI`, via
   `IMeterFactory`) with one bounded tag `result` (`guaranteed`, `shared`, `capacity_exceeded`, `concurrency_exceeded`,
   `not_needed`); warning EventId 1200 (client ID and limit) at most once per client per minute, EventId 1201 for an
   unknown client without its value.

## Why not …

- **Fall back to deterministic-only on exhaustion (like a provider 429):** an attacker-controlled switch that turns the
  AI layer off. A provider 429 cannot be attributed to a caller; AgentShield's own refusal can, and per-client shares
  keep one client's exhaustion from reaching the others.
- **Fixed (calendar) windows:** up to twice the limit across a boundary; a UTC-midnight reset can allow 2 × 400 inside
  one provider (Pacific-time) day. A sliding log is exact and cheap at these sizes.
- **A waiting queue:** holds requests (and connections) behind a 3 s provider call and turns overload into latency for
  everyone; refusing at once and reviewing is predictable.
- **Only a per-minute guarantee:** one client could still spend the whole daily budget in under two hours and push the
  others into Review for the rest of the day, hence daily shares too.
- **Deriving the client population from traffic:** a client that has not called yet would have no reservation; the
  configured client set is known at startup and bounded.
- **Redis / distributed state:** one instance today; the port allows a shared-store implementation later (own ADR).

## Consequences

- With AI disabled (both committed appsettings files) nothing changes: the stage returns `Disabled` before asking the
  gate, and capacity settings are not validated.
- With AI enabled, deterministic Blocks no longer call the provider (fewer calls, no 3 s wait; audit `AiStatus`
  `NotNeeded`). Existing tests about AI findings next to a deterministic Block turn the skip off explicitly.
- A client that spends its AI budget gets Review (not Allow) for inputs the deterministic rules would allow, until its
  window rolls; other clients keep their guarantees. With the defaults at most five analysis clients fit the
  guarantees; more require a larger global budget (startup fails otherwise).
- Concurrency has no per-client guarantee: clients at their concurrency limit can briefly occupy all global slots
  (bounded by their request budgets and the 3 s timeout); the others then get Review for those seconds.
- State is per process and resets on restart; several instances would each apply the full budget. Tokens are not
  counted (bounded indirectly by the request budget; see ai-analysis.md section 16).
- Not built here: circuit breaker, canary, degraded mode, distributed state, per-client configuration, token budget.
- Full specification: [docs/security/ai-analysis.md](../security/ai-analysis.md), section 16.
