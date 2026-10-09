# 0012 — AI-assisted analysis boundary: findings only, guarded centrally, failures by cause

- **Status:** Accepted — 2026-09-29. The provider-side fallback to the deterministic decision (unavailable, rate
  limited, network) is superseded by [0016](0016-ai-provider-circuit-breaker-and-input-token-budget.md): those failures
  now hold the input for review, and a circuit breaker bounds their cost.
- **Extends:** [0010](0010-deterministic-firewall-pipeline.md) (policy decides, fail closed) and
  [0011](0011-bounded-obfuscation-detection-and-finding-fusion.md) (finding fusion, fail-safe limits). Nothing is
  superseded.
- **Extended by:** [0013](0013-gemini-provider.md) (first provider: Gemini; options section `Ai`, key
  `Ai:Gemini:ApiKey` from User Secrets; `AiAnalysisErrors.RequestRejected`) and [0015](0015-ai-capacity-gate.md)
  (AI capacity gate; statuses `CapacityExceeded` → Review and `NotNeeded` for deterministic Blocks).

## Context

The firewall is to use an LLM as an additional analysis signal (paraphrased and non-English attacks that keyword rules
miss). An LLM judging attacker-controlled text can itself be manipulated by that text, is non-deterministic, reports
uncalibrated confidence, and fails in new ways (timeouts, rate limits, refusals, malformed output). The deterministic
pipeline must keep working, unchanged, when no provider is available. No provider is chosen yet.

## Decision

- **AI returns findings, never decisions.** The output contract is a list of findings in a closed vocabulary
  (`AiFindingCatalog`: `{Category}.AiDetected`), with no field for a decision, score or verdict. Findings join the
  deterministic ones in the existing `IFindingAggregator`, risk engine and policy engine. No AI-specific risk engine.
- **Two ports.** `IAiSecurityAnalyzer` (Application; implemented in `AgentShield.AI`) is one provider and returns the
  **raw, untrusted** answer (`AiAnalysisOutput`, strings and nullables). `IAiAssistedAnalysis` (Application;
  implemented in Security as `AiAssistedAnalysis`) is the guarded stage the use case calls. Validation, mapping,
  timeout and failure handling live in the guard, so no provider adapter can skip or weaken them. The provider port
  deliberately does not return `ThreatFinding`s.
- **Strict, all-or-nothing validation.** Syntax in the AI project (`AiStructuredOutputParser`: 32 KiB, one JSON
  object, no unknown/duplicate/differently cased members, strict types). Meaning in Security (`AiResponseValidator`:
  exact enum names, catalogue code matching its category, confidence 0–1, ≤ 16 findings, description ≤ 500). One
  violation rejects the whole answer. Model-written descriptions are validated and discarded; clients see catalogue text.
- **AI can only add.** AI codes never equal deterministic codes, so fusion never merges them; the AI cannot lower,
  rewrite or remove a deterministic finding. The highest severity sets the risk level as before. AI-only findings can
  escalate (High/Critical → Block). Confidence is kept but does not affect the score.
- **Failures are handled by cause.** Failures positively identified as provider-side (unavailable, rate limited,
  network) fall back to the deterministic decision. Failures the input could cause (timeout, malformed or invalid
  answer, refusal, content withheld, unclassified) add `InconclusiveAnalysis.AiAnalysisIncomplete` (Medium → Review)
  via a new `ThreatCategory.InconclusiveAnalysis`, so the policy engine still makes the decision. Exceptions fail closed
  (500), as in ADR 0010. No retries.
- **Hard 3 s timeout** from a linked `CancellationTokenSource(timeout, TimeProvider)` plus `WaitAsync`, so even an
  adapter that ignores cancellation is abandoned on time.
- **Disclosure policy before any provider call** (`IAiDisclosurePolicy`): normalised text only, secrets masked, withheld
  (Review) if over 65,536 characters or if redaction times out; never truncated. The extension point for PII and
  provider-specific data rules.
- **Audit:** `SecurityEvent.AiAnalysis` (`AiAnalysisSummary`: status, provider, model, finding count, duration) is
  logged with every security event. Prompts, content and provider answers are never logged. AI status is not returned to
  clients.
- **Enabled by registration.** AI analysis runs only if an `IAiSecurityAnalyzer` is registered; `AddAI` registers none
  yet. Options (`AiAnalysis:Enabled`, provider, model) arrive with the first real provider. The test double stays in the
  test projects.

## Consequences

- With AI disabled (the only state in the running API today), every decision equals Milestone 2's; the only contract
  change is the additive `ThreatCategory.InconclusiveAnalysis` value (and, when a provider is enabled, the
  `*.AiDetected` and `InconclusiveAnalysis.AiAnalysisIncomplete` codes).
- A provider outage degrades to deterministic-only; a content-induced analyser failure costs a Review, never an Allow.
  A provider that is slow for everyone turns into Review for everyone until a circuit breaker (with the first provider)
  converts it into `Unavailable`.
- A manipulated or wrong model can cause false Blocks (availability), never a bypass of a deterministic Block.
- Adding a provider means one adapter class in `AgentShield.AI` that maps its API to `AiAnalysisRequest` /
  `AiStructuredOutputParser` / `AiAnalysisErrors`; nothing in Application, Security or Api changes.
- Full specification: [docs/security/ai-analysis.md](../security/ai-analysis.md).
