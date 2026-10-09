# 0017 — AI evaluation tooling project (`tests/AgentShield.Evaluation`)

- **Status:** Accepted — 2026-09-30 (Milestone 7.1, evaluation hardening)
- **Extends:** [0001](0001-modular-monolith-clean-architecture.md) (project structure). Production architecture unchanged.

## Context

Milestone 7 measured the AI signal with a single-file script (`scripts/ai-evaluation.cs`, a .NET 10 file-based app).
Its first real run stopped after six Gemini calls on a timeout, and it recorded the timed-out case before the abandoned
call ended (that call's status and latency were lost). A final, citable evaluation needs a runner whose safety and
honesty rules are tested: resume without re-sending completed fixtures, one attempt per fixture, stop on the first
429, the second 5xx or a timeout, never exceed a hard cap, never send deterministic Blocks, never write inputs, prompts,
answers, descriptions or keys. A file-based script cannot be referenced by the test projects, so none of that could be
tested by `dotnet test`.

## Decision

1. **A tooling project `tests/AgentShield.Evaluation`** (console application, in `AgentShield.slnx`, same build gates),
   replacing the script. It references `AgentShield.Api` only to host the real API in memory (`WebApplicationFactory`,
   Development environment, committed configuration) and measures it through `POST /api/v1/firewall/analyze`.
2. **Nothing in `src/` references it, and it is never deployed.** It lives under `tests/` and holds no production code:
   dataset model, results store, planner, stop rules, outbound observer, virtual clock, report.
3. **`AgentShield.IntegrationTests` references it** (via `InternalsVisibleTo`) and tests the runner end to end with a
   fake provider transport and a virtual clock: no request can reach Google from a test.
4. **Structural safety:** outside a real run the outbound observer answers from a supplied fake transport and never
   forwards; in a real run it lets through only `generateContent` to the pinned host, below the hard cap, and only
   while a fixture that the deterministic rules do not block is being sent. A real run accepts only the committed
   configuration, the system clock and the provider limits stated by the operator (the run stays at or below half).
5. **Results are safe metadata committed with the repository** (`tests/Evaluation/results`): append-only JSONL of
   attempts and sessions, the deterministic baseline, and the generated report; attempts are combined only while the
   fixture texts (input fingerprint) and the deterministic results (baseline fingerprint) are unchanged.

## Why not …

- **Keep the file-based script:** its behaviour could not be tested; the timeout bug was found only by a real run.
- **Put the runner inside `AgentShield.IntegrationTests`:** a test assembly is not a runnable tool, and a real run must
  never be part of `dotnet test` (automated tests never call Google, no skipped tests).
- **A project under `src/`:** evaluation tooling is not part of the product and must not become a dependency of it.

## Consequences

- One more project in the solution; it builds with warnings as errors. `dotnet test` ignores it (not a test project).
- The runner is started with `dotnet run --project tests/AgentShield.Evaluation -- <command>`
  (`docs/security/ai-analysis.md`, section 18).
- The Milestone 7 session-1 results were converted into the new store format (documented in the session record).
