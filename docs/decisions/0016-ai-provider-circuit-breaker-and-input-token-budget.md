# 0016 — AI provider circuit breaker, input-token budget, and Review on provider unavailability

- **Status:** Accepted — 2026-09-30 (Milestone 6, step 2). Amended 2026-09-30 (Milestone 6, step 3): Gemini HTTP
  401/403/404 are rejected requests, not availability failures, and no longer open the circuit (see Consequences).
- **Extends:** [0015](0015-ai-capacity-gate.md) (AI capacity gate). **Supersedes** the part of
  [0012](0012-ai-analysis-boundary.md) under which provider-side failures (unavailable, rate limited, network) fall back
  to the deterministic decision.

## Context

After step 1, AgentShield budgets AI requests but not input tokens, and Google limits input tokens per minute per
project (observed free tier: 250,000). One request can carry 32,000 characters, and in scripts that tokenise at about
one token per character ten such requests could exceed that limit.

Provider failures were handled by ADR 0012's table: 429, 5xx and network failures fell back to the deterministic
decision. Because the deterministic rules miss attacks that only the AI detects, anyone able to push the shared Google
quota into 429s (or wait for an outage) could get those attacks through as Allow. And with no circuit breaker, every
analysis during an outage waited for its own failure (up to 3 s) and kept loading a provider that was already refusing.

`Google.GenAI` 1.22.0 offers no local tokenizer: `CountTokensAsync` and `ComputeTokensAsync` are network calls. The
response carries `usageMetadata.promptTokenCount`, but only after the call.

## Decision

1. **Every failure of an expected AI analysis holds the input for review** (`AiFailurePolicy`): provider availability
   failures (`RateLimited`, `Unavailable`, `NetworkFailure`, `TimedOut`) included. A deterministic Block always blocks.
2. **Provider-agnostic circuit breaker**, port `IAiCircuitBreaker` (Application), `InMemoryAiCircuitBreaker`
   (Infrastructure): one circuit per process for the configured provider and model. Closed → Open after
   `FailureThreshold` (3) consecutive availability failures; Open for `OpenDurationSeconds` (30), then HalfOpen with
   exactly one probe permit (bounded by `HalfOpenProbeTimeoutSeconds`, ≤ the stage's 3 s); probe answered → Closed,
   probe failed → Open, probe released without an outcome → slot free, lost probe → Open after its timeout plus 1 s.
   New status `AiAnalysisStatus.CircuitOpen` → Review. Only `AiProviderAvailability.IsAvailabilityFailure` outcomes
   count; any provider answer (including 400, malformed or invalid output, refusal) resets the count. That
   classification lives once in Application on the stage's normalised statuses; no provider status code reaches the
   breaker. **No retries.**
3. **Order in the stage:** Block skip (`IAiCapacityGate.IsCallNeeded`) → disclosure → token estimate → circuit →
   capacity → one call → report the outcome. The circuit is asked before capacity, so an open circuit consumes nothing;
   a Block touches neither.
4. **Input-token budget** in the existing gate: a rolling per-minute token budget with the same guarantee/maximum
   rules as requests (`GlobalInputTokensPerMinute` 200,000; per client 40,000 guaranteed / 80,000 maximum), using a
   weighted `RequestBudget` (identical behaviour for amount 1). Each admitted call reserves its estimate for 60 s,
   whatever the outcome; refusals reserve nothing; no refund, no after-the-fact charge.
5. **The estimate is local and conservative:** `IAiSecurityAnalyzer.EstimateInputTokens` (the adapter counts one token
   per UTF-8 byte of everything it sends, plus a framing allowance), never below the stage's provider-agnostic floor
   (one token per UTF-8 byte of the content and context). Never a provider token-count request. The Gemini adapter logs
   EventId 1101 if Gemini ever reports more input tokens than estimated.
6. **Observability:** transitions logged (EventId 1300); bounded metrics for transitions, rejections, probes, provider
   failure kinds, token admissions and reserved tokens.

## Why not …

- **Deterministic-only on provider failure (ADR 0012's rule):** an attacker-reachable switch that turns the AI off.
  The breaker bounds the availability cost of Review instead.
- **Provider `countTokens` per request:** a second network call per analysis costs quota and latency and adds a failure
  mode. **Reconciling the budget from reported usage:** needs usage in the provider contract, makes the budget depend on
  provider-reported numbers, and gains headroom that is not needed while the request budget binds first.
- **`characters / 4`:** under-counts CJK, emoji and Base64-like text by several times.
- **Retries or a queue:** add load when the provider has least capacity and give attackers more leverage.
- **A per-client circuit:** an outage is not per client; per-client state would let one client's traffic keep probing.
- **A distributed breaker / Redis:** one instance today; the ports allow it later with its own ADR.

## Consequences

- With AI enabled, an outage or quota exhaustion means Review for every input the deterministic pipeline would allow:
  first for the calls that open the circuit (at most 3 s each), then immediately while it is open. Deterministic Blocks
  are unaffected. This trades availability (review load) for the absence of a bypass.
- Content that makes the model time out counts as an availability failure: a client alone on the system could open the
  circuit with three such inputs (Review for everyone for 30 s; not a bypass). Interleaved successful calls keep it
  closed.
- Very large inputs (with the committed values, CJK text above about 25,600 characters) can never be AI-analysed and
  are held for review.
- A misconfigured provider does not open the circuit: an invalid Gemini key (HTTP 400) and, since step 3, a revoked or
  blocked key, a missing permission or an unknown model (HTTP 401/403/404) are `RequestRejected` (`UnclassifiedFailure`):
  Gemini answered, and waiting does not fix a configuration fault. Every such input is held for review, one provider
  call each (bounded by the capacity gate). Step 2 had classified 401/403/404 as `Unavailable`, which opened the
  process-wide circuit, reported a configuration fault as an outage and kept it flapping open → half-open → open.
- State stays process-local: several instances would each keep their own budget and circuit.
- Full specification: [docs/security/ai-analysis.md](../security/ai-analysis.md), section 17.
