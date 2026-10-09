# 0022 — Attack Lab: a thin demonstration layer over the real API, a counts-only activity summary, and the tool gateway's failure entry on cancellation

- **Status:** Accepted — 2026-10-07 (Milestone 12)
- **Builds on:** [0019](0019-security-activity-history.md) (activity history), [0020](0020-agent-action-authorization-boundary.md)
  (authorization boundary), [0021](0021-tool-gateway-enforced-execution.md) (tool gateway), [0009](0009-strict-json-input.md)
  (strict JSON), [0018](0018-assurance-tooling.md) (browser checks). Changes no detector, threshold, policy rule, AI,
  capacity or circuit setting.
- **Specification:** [attack-lab.md](../security/attack-lab.md).

## Context

AgentShield's controls (input firewall, authorization boundary, tool gateway) could each be exercised from their own
page, but a reviewer had to know the implementation to see the point: ATTACK → DETECT → DECIDE → ENFORCE → EVIDENCE was
not visible in one place. A demonstration surface is an attractive place to cheat: precomputed results, a decision
"expected" by the scenario shown in place of the real one, a shortcut to the tool, counts that look like telemetry.
Each of those would make the demo dishonest and, worse, a second security implementation that could drift from the real
one.

## Decision

1. **A console feature, no backend demo endpoint.** `src/features/attack-lab` holds a static catalogue of 14 scenarios
   (9 inputs, 5 tool calls) and sends each one, unchanged, to `POST /api/v1/firewall/analyze` or
   `POST /api/v1/agent/tools/execute`, as the public Development client (research-agent's gateway identity). The API has
   no Attack Lab endpoint, flag or code path; it cannot tell a demo request from any other.
2. **No security logic in the console.** It never decides, scores, authorises or runs anything. Results are rendered from
   the response; a scenario's intent is shown beside it and compared informationally only; unknown values are never
   echoed; a tool is shown as run only when the decision, `executed` and the outcome agree.
3. **Deterministic and provider-free.** The scenarios are written for the deterministic rules with AI off; their decisions
   are pinned through the real pipeline by `AttackLabScenarioTests` (a detector change that breaks a demonstration
   fails there). No new detector was written for them; the paraphrase they miss is shown as a known miss (I-09).
4. **One deliberate contract violation.** The replay scenario's second request carries an `executionId`. It exists to be
   rejected (400 before any decision). Grants never leave the process, so a real replay cannot be shown from a client;
   the page says so and points to the tests that prove single use.
5. **`GET /api/v1/activity/summary`** (`IActivitySummaryUseCase` → `ActivitySummaryUseCase`, `activity:read`, `Standard`
   rate limit): total, per decision, per kind, tools that ran, oldest and newest time, from **one** read of the store, so
   the numbers are one consistent snapshot. Counts only (no IDs, names or content). Chosen over a `kind` filter on the
   list endpoint, which would need several requests (and could disagree between them) and widen a query surface for no
   gain. The console labels the counts as this process's in-memory history, never as a period.
6. **Activity kinds visible.** Activity rows carry a kind badge (Input, Agent action, Tool call); the read model is
   unchanged.
7. **Metadata-only export** built in the browser from an allowlist (no payload, argument, result, server text or pass
   field).
8. **Dev and preview servers without CORS** (`server.cors` / `preview.cors` `false`, H-08): the Vite proxy adds the
   Development key, so no other local origin may read through it.
9. **Tool gateway: the failure entry is written whatever ended the call (D-21).** After the grant is consumed, any
   exception from the tool, cancellation included, records `ToolExecutionFailed` with a token of its own and then
   propagates. Before, a cancelled call left `ToolExecutionStarted` as the last entry (or skipped recording when the
   request's own token was cancelled).
10. **Its own chunk.** The page is lazy-loaded so the core console's bundle stays below Vite's size advisory.

## Consequences

- One new endpoint, one new use case, no new permission. Pinned endpoint inventory, OpenAPI and field-set tests updated
  deliberately.
- The console grows a fifth navigation item; the header layout switches to one row from `lg`.
- Invariants 71–73 (attack-lab.md, security-invariants.md); invariant 68 amended for D-21.
- **Not built:** a backend scenario runner, scenario persistence, scheduled or automated red-team runs, an approval
  workflow for Review, AI-assisted scenarios, a report server or PDF, real tools behind the gateway.
