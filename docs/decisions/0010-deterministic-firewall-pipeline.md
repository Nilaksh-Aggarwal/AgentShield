# 0010 — Deterministic firewall pipeline with fail-closed stages

- **Status:** Accepted — 2026-09-29

## Context

Milestone 1 delivers the first security feature, `POST /api/v1/firewall/analyze`. It needs a shape that later stages
(AI-assisted analysis, persistence, tool gateway) can join without rewriting it. It also has to settle what happens
when a stage fails, because a firewall that answers "Allow" after its detection broke is worse than none.

## Decision

- **One port per stage, orchestrated in Application.** `AnalyzeInputUseCase` calls `IInputNormalizer` →
  `IEnumerable<IThreatDetector>` → `IRiskEngine` → `IPolicyEngine` → `ISecurityEventSink`. The use case holds no
  security rules. Normalisation, detection, risk and policy live in Security; the event sink is an I/O adapter in
  Infrastructure; the correlation ID reaches Application through `ICorrelationContext`, implemented in Api.
- **Detectors are independent classes**, all resolved through `IEnumerable<IThreatDetector>` (convention registration,
  ADR 0008). They report findings and never decide.
- **Only the policy engine decides.** The risk engine only scores. Future AI output enters as findings, never as a
  decision.
- **Domain owns the vocabulary:** `ThreatFinding`, `ThreatSeverity`, `ThreatCategory`, `RiskAssessment` (level derived
  from score), `SecurityDecision`, `PolicyDecision`, `SecurityEvent`.
- **Fail closed.** A detector exception, a regex timeout or a sink failure is not caught. The request fails with 500
  and no decision is returned. A decision is never returned without being audited.
- **Linear-time detection.** Every pattern uses `RegexOptions.NonBacktracking` plus a timeout; a test enforces this for
  every rule.
- **No input in findings, events or logs.** Findings carry fixed descriptions and evidence (rule ID, match count).
  Evidence is logged but not returned to clients.

## Consequences

- A new detector is one class plus tests. A new policy is one class (or new constants) plus tests.
- A buggy detector takes the endpoint down (500) instead of silently weakening it. That is intended, but detector
  code needs the same care as the policy.
- Callers must treat 500 as "not analysed" and must not forward the input.
- Persistence can replace or join `LoggingSecurityEventSink` behind `ISecurityEventSink` without changing the use case.
