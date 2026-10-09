# 0018 — Assurance tooling: mutation testing, frontend tests, committed browser checks

- **Status:** Accepted — 2026-10-01 (Milestone 8, Assurance)
- **Extends:** [0002](0002-build-quality-gates.md) (quality gates). Production code, detection baseline and API unchanged.

## Context

By the end of the hardening reviews the backend had about 1,500 tests. Only a few of them had been shown to fail when
the code is wrong. Mutation checks were done by hand, one fault at a time, and covered a fraction of the security core.
The normaliser, fusion, risk engine, policy thresholds, authentication and rate limiting had none. The console had no
test runner. Its headless-browser checks (836 on the Analyze page, 375 on the other pages) were throwaway scripts outside
the repository, so they protected nothing after the day they ran.

Milestone 8 had to measure how well the tests catch faults and protect the console, without changing what AgentShield
decides.

## Decision

1. **Stryker.NET as a local dotnet tool** (`dotnet-tools.json`, version pinned), with one configuration per scope in
   `tests/mutation/`:
   - `stryker-security.json`: the whole Security project against SecurityTests;
   - `stryker-ai-capacity.json`: the capacity gate, circuit breaker and token budget against UnitTests;
   - `stryker-api-boundary.json` and `stryker-api-boundary-integration.json`: authentication and rate limiting, once
     against ApiTests and once against IntegrationTests. `merge-reports.mjs` combines the two reports: a mutant counts
     as detected if either run detects it. A single run with both test projects reported four mutants as surviving that
     ApiTests kill on their own, and attributed only 16 of 270 kills to ApiTests, so that configuration is not used.

   Runs are on demand (`dotnet stryker --config-file …`), not part of `dotnet test`. They take minutes per scope and
   there is no CI. The break threshold is 0. A score is evidence, not a gate, and a gate would reward chasing 100%. Every
   survivor is classified as a real test gap, an equivalent mutant, a redundant or unreachable mutant, or a tooling
   limitation. A real gap gets the smallest test of real behaviour that kills it. Production code is never changed only
   to remove an equivalent mutant. Reports go to `tests/mutation/StrykerOutput/` (ignored by Git). The results and the
   triage are recorded in `docs/PROGRESS.md` and `docs/security/test-coverage-summary.md`.
2. **Vitest, Testing Library and jsdom** as frontend dev dependencies (`npm test`). Tests cover what a user sees and what
   a module promises: presentation functions, rendered text and roles, the API client's error mapping. `fetch` is stubbed
   with `vi.stubGlobal`, so nothing reaches a server. Component internals are not tested.
3. **The browser checks are committed but stay plain Node scripts** (`frontend/agentshield-web/e2e`, `npm run
   test:e2e`). They drive headless Chrome or Edge through the DevTools Protocol with Node's built-in `fetch` and
   `WebSocket`, against two real API instances (AI forced off) and the production build. They are not converted:
   - **Not to Vitest.** jsdom has no layout, colour or real focus. 281 of the 836 Analyze checks and 165 of the 375
     Overview checks are page semantics, overflow at 375/768/1280 px, WCAG contrast in both colour schemes, touch-target
     size and focus rings. The rest check behaviour and privacy against the real API's 200/401/403/422/429/500 responses
     over HTTP. Representative cases of that behaviour already live in the component tests (decision, privacy, errors,
     `Retry-After`) with stubbed responses. Moving the rest would duplicate those tests and lose the real-API part.
   - **Not to Playwright or Vitest browser mode.** Either adds a dependency and a browser download and proves nothing the
     scripts don't already prove. Rewriting 1,211 working checks risks losing some of them.
   - **Kept out of `npm test` and `dotnet test`.** They need a built API, a production build, free local ports and a
     local Chrome or Edge, and they take minutes. CLAUDE.md requires them when the UI changes.
4. **No coverage percentages** until a coverage tool has actually been run and its output recorded. Milestone 8 adopted
   none: mutation scores say more about the security core than line coverage does.

## Consequences

- Mutation evidence exists for the scopes above and is reproducible with one command per scope. Code outside them has
  no mutation run: the Gemini adapter, the use case, error handling, JSON input policy, CORS and headers. They still have
  their hand-made mutation checks (test coverage summary).
- Two frontend layers with distinct jobs. The Vitest tests run in seconds and protect presentation and privacy logic.
  The browser checks protect layout, accessibility and the real HTTP contract, and run only on demand.
- The browser scripts are code to maintain. They are smaller than a Playwright setup, have no dependencies, and are
  documented in `e2e/README.md`.
- No JavaScript mutation tool. The frontend tests were checked with hand-made mutants (recorded in PROGRESS). StrykerJS
  can be added later if the console grows decision-relevant logic.

## Alternatives considered

- **Stryker in a CI gate:** no CI exists, and adding CI/CD is out of scope.
- **Playwright Test:** the standard choice for a larger UI, but not needed for two pages already covered by working
  scripts.
- **Coverlet line coverage:** cheap to add, but line coverage shows that code ran, not that a test would notice it
  breaking. Deferred, not rejected.
