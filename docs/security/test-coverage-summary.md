# Test coverage summary

Which tests prove each security area, at which level, and how strong the evidence is that those tests would catch a
fault. Built from the test projects, the Milestone 8 mutation runs (2026-10-01), the Milestone 10 runs on the agent action
authorization code, the Milestone 11 runs on the tool gateway, the Milestone 12 runs on the activity summary, the
D-21 change and the Attack Lab console, and the Milestone 13 runs on human approval and input binding (all 2026-10-07). For what each area defends
against, and its limits, see the [security coverage matrix](security-coverage-matrix.md). The defects behind the
regression tests are in the [defect matrix](defect-matrix.md), and the properties the tests establish are in
[security invariants](security-invariants.md).

Five kinds of evidence appear below. They are not interchangeable:

| Kind | What it shows | What it does not show |
|---|---|---|
| **Test coverage** (automated tests) | The behaviour each test name states, for the inputs it uses | That other inputs or other defects behave |
| **Mutation coverage** (Stryker.NET, hand-applied mutants) | That the tests fail when the code under them is changed | Anything about code outside the mutated scope |
| **Browser verification** (`e2e` scripts) | The console in a real browser against the real API, on demand | Anything between runs: not part of `dotnet test` or `npm test` |
| **Security invariants** | Which properties hold, and what evidence supports each | Detection breadth (which attacks are recognised) |
| **Limitations** | What is known not to be covered | — |

**No code-coverage tool has been run, so this document gives no line or branch coverage percentages.** The only
percentages here are mutation scores.

## Test levels and counts

| Level | Project | What it exercises | Test cases |
|---|---|---|---|
| Unit | `AgentShield.UnitTests` | Domain (incl. agent names, profiles, verdicts, grants, outcomes, the gateway lifecycle), Application (use cases incl. the tool gateway, results, validation, DI conventions, activity record, recorders and query), Infrastructure logic (capacity gate, circuit breaker, token budget, activity store, agent directory and gateway identities, audit sinks, the reference tool) with fake clocks; the activity summary; approvals, the approval and input-context stores, the shared sink contract | 837 |
| Unit (security) | `AgentShield.SecurityTests` | Normaliser, detectors, obfuscation, fusion, risk, policy, redaction; AI parser, validator, failure policy, disclosure, stage; the Gemini adapter through the real SDK against a fake transport; decision-core boundary tests and robustness properties; agent action risk, policy, catalogue, authorizer and attack scenarios; the gateway's argument policy and execution authority (with the approval check) | 1,082 |
| HTTP | `AgentShield.ApiTests` | HTTP contract through `WebApplicationFactory`, some on real Kestrel: status codes, Problem Details, authentication, authorization, rate limits, CORS, headers, strict JSON, the activity, activity summary, agent action and tool gateway endpoints (the gateway with a probe on every tool executor); every Attack Lab scenario through the real pipeline; the approval endpoints and input binding over HTTP | 565 |
| Integration | `AgentShield.IntegrationTests` | Full composition: DI graph, whole pipeline with scripted AI providers, log sinks, health, startup validation, evaluation tooling, the Gemini client against a loopback server, the activity history, the agent action boundary, the tool gateway (complete mediation over every AgentShield type), approvals end to end with the audit log, startup failures reported as themselves (X-05) | 262 |
| **Backend total** | | `dotnet test AgentShield.slnx`, 2026-10-07 (Milestone 13) | **2,746** |
| Frontend | `frontend/agentshield-web` (Vitest, Testing Library, jsdom) | Presentation logic, the API client, the Analyze, Activity and Agent security pages (incl. the tool gateway preview), the Attack Lab (incl. the T-04 approval flow), the approval panel and the Overview's security operations against a stubbed `fetch` | 387 in 21 files |
| Browser checks | `frontend/agentshield-web/e2e` (Node and headless Chrome) | The production build against two real API instances (AI forced off) | 836 Analyze + 479 Overview/Activity + 379 Agent security + 424 Attack Lab checks (2,118) |

Milestone 13 added 156 backend test cases (2,590 → 2,746: Unit +104, Security +11, Api +28, Integration +13) and 39
frontend tests (2 new files), for human approval, input binding, the shared sink contract, D-22 and X-05. Existing tests
changed only where a contract changed deliberately (two new outcomes and fields, the input recorder among the sinks, the
cancellation test that pinned the old D-23 behaviour, T-04); none was weakened or removed (details in PROGRESS.md).

Milestone 12 added 53 backend test cases (2,537 → 2,590: Unit +7, Api +46; Security and Integration unchanged), 75
frontend tests in 6 new files and the Attack Lab browser suite, for the Attack Lab, the activity summary, the Activity kind
badge, the Agents flow and D-21. Existing tests changed: the M11 test that pinned the old cancellation behaviour (replaced
by the two D-21 tests), the Tab counts of three browser suites (a fifth navigation tab), and the Agents suite's Activity
checks, which read text content because a spoken ": " now follows each kind badge. None was weakened or removed.

Milestone 11 added 390 backend test cases (2,147 → 2,537: Unit +182, Security +67, Api +121, Integration +20), 26
frontend tests in 3 new files and 78 browser checks, for the tool gateway, its activity records and its console preview.
Existing tests changed only where a contract changed deliberately: the pinned catalogue (16 actions, 15 capabilities,
`knowledge.lookup` Low) and the two exhaustive authorizer counts (× 16 actions); the activity field sets
(`toolExecution`, `ActivityToolExecution`, the `ToolExecution` kind) in `SecurityActivityRecordTests`,
`ActivityEndpointTests` and `ActivitySwaggerTests`; the directory validator's message for a bound client (it now accepts
`tool:execute`); three test doubles gained the new port members; and the console copy that said "Nothing is executed" (one
Vitest assertion each in two tests, one browser check). None was weakened or removed.

Milestone 10 added 362 backend test cases (1,785 → 2,147: Unit +174, Security +101, Api +66, Integration +21) and 52
frontend tests, all for the agent action authorization boundary, its activity records and its console preview, plus a
new browser suite. Existing tests changed only where the activity contract changed deliberately (`agentAction` field,
nullable score and AI status): the pinned field sets in `SecurityActivityRecordTests`, `ActivityEndpointTests` and
`ActivitySwaggerTests` include the new fields, `SecurityActivityRecordTests` compares the copied risk by value instead of
by reference, `ListActivityUseCaseTests` expects `ActivityRiskResponse`, the client-directory test double gained the new
member, and the Analyze and Overview browser suites press Tab once more past the four navigation links. None was
weakened or removed.

Milestone 9, step 1 (after Milestone 8) added 161 backend test cases (1,624 → 1,785: Unit +104, Security +11,
Api +42, Integration +4) and 51 frontend tests. Of these, 12 are the D-18 regression cases (1 replaces the test that
pinned the defect), the rest cover the activity history and D-19. Existing tests changed: the D-18 pinning test became
`InputContainingUFFFE_IsAnalysed_AndDecidedLikeTheSameTextWithoutIt_D18`; `AnalyzeInputUseCaseTests` passes a list of
sinks; `FirewallCompositionTests` and the endpoint inventory test assert both sinks and the activity policy; the
Overview browser suite's Activity section checks the real page instead of the placeholder (375 → 460 checks).

Milestone 8 added 137 backend test cases (1,487 → 1,624). They fall into four groups:

- decision-core boundary tests (40);
- robustness properties (35);
- one test that pins the open defect D-18;
- the tests that close the gaps mutation testing found.

It also added the frontend test runner, with 144 tests, and committed the browser checks. Existing tests
changed in only two ways. Assertions were strengthened: the monotonicity tests state decision strictness explicitly
instead of using enum order, and the startup-validation helper checks that the message names the setting and never
repeats a hash. Existing test classes also gained new rows. No test was removed or weakened.

## Mutation testing

### Milestone 13: human approval, input event binding, recording, X-05 (2026-10-07)

Four focused Stryker scopes for the new backend code (`tests/mutation/stryker-approval-*.json`), each run alone (no other
build while Stryker builds), then hand-applied mutants for what Stryker cannot reach.

| Scope (config) | Code mutated | Tests | Mutants created | Valid | Detected | Survived | Mutation score | First run |
|---|---|---|---|---|---|---|---|---|
| `stryker-approval-domain` | `ToolApproval` (binding, statuses, decide, use, revoke), `ToolApprovalEvent`, `ToolGatewayEvent`, `ToolExecutionOutcome` | UnitTests | 233 | 144 | 120 | 24 | **83.33%** | 71.53% |
| `stryker-approval-application` | `ToolGateway`, approval use cases and response, `EventSinks`, `InputSecurityContextRecorder`, `InputSecurityContext` | UnitTests | 153 | 71 | 60 | 11 | **84.51%** | (final) |
| `stryker-approval-infrastructure` | `InMemoryToolApprovalStore`, `InMemoryInputSecurityContextStore` | UnitTests | 167 | 55 | 46 (1 timeout) | 9 | **83.64%** | 81.82% |
| `stryker-approval-security` | `ExecutionGrantAuthority` (with the M13 `UsedFor` check) | SecurityTests | 105 | 72 | 64 | 8 (2 no coverage) | **88.89%** | (final) |

Every mutant in the M13 decision code that Stryker could compile and that changes behaviour is killed: `Verify` (input
reference), `Strictest`, `HoldAsync`, `EventSinks`, `UsedFor`, `TryUse`, `TryBeginDecision` / `CompleteDecision`, the
binding's digest check. The application scope run was the one after the D-22 fix (an earlier run was stopped when the fix
began; its output is under `StrykerOutput/aborted`).

| Category | Count | Mutants | Why |
|---|---|---|---|
| a. Real gap | 0 left (8 closed) | Digest check `Any` → `All`; empty referenced input event; empty approval ID in a refusal; rejection codes recorded only with their own outcome (2); `ToolApprovalEvent` refusing a non-decision (2); the binding's `ToString`; the store's "evict only when full" check | Focused tests (T-11 in the defect matrix); all killed in the final runs |
| b. Equivalent | 42 | Exception messages (Domain 24, Application 8, Infrastructure 3, Security 2); `Strictest` with `>=` → `>` (equal ranks are the same decision); the M11 signature encoding in the authority (length check before `FixedTimeEquals`, `leaveOpen`, the context label: signing and verifying use the same bytes) | Behaviour unchanged; messages never reach a client |
| c. Defensive | 8 | Null and range guards on values nullable analysis already excludes (store and recorder parameters, `ToolApprovalResponse.From`, `Recent(count)`, `TryUse(presented)`) | Kept as defence in depth |
| d. Unreachable | 2 | "An execution ID was issued twice" (a v7 GUID collision) | — |

**Stryker cannot compile any mutant inside `ToolGateway.ExecuteAsync`** (45 compile errors: Stryker rolls the whole
method back). In Milestone 12 the same method had 23 valid mutants; the Milestone 13 branches (pattern variables carried
across the input, approval and grant stages) make every placement fail. That method is where Review is held, the approval
used and the input reference enforced, so it was covered with hand-applied mutants instead.

**Hand-applied mutants (Milestone 13).** Same procedure as M11 and M12: hash the file, apply, run the named tests
(incremental build), restore, touch, check the hash is identical; then one `--no-incremental` build of the solution. Two
mutants first failed to compile (`if (false)` trips CS0162, and an unread primary-constructor parameter trips CS9113 —
warnings are errors); both were rewritten to compile and then killed. **All 28 killed.**

| Mutant | Tests that failed |
|---|---|
| HM-01 A Review is never held (falls through to the grant) | 19 UnitTests (`ToolGateway*`), 19 ApiTests (approval, Attack Lab) |
| HM-02 A rejected approval is ignored and treated as used | 6 UnitTests, 5 ApiTests (the authority still refuses: 500, nothing runs) |
| HM-03 An input event that cannot be verified is ignored | 4 UnitTests, 4 ApiTests |
| HM-04 The server's record of the input is ignored | 7 UnitTests, 6 ApiTests |
| HM-05 The caller's own (tightening) report is ignored | 3 UnitTests |
| HM-06 The input decision a presented approval was held under is ignored | 1 UnitTest, 2 ApiTests |
| HM-07 The approval does not bind the arguments (constant digest) | 1 UnitTest, 1 ApiTest |
| HM-08 A new approval does not carry the verified input event | 1 UnitTest |
| HM-09 The gateway does not tell the authority which approval was used | 1 UnitTest |
| HM-10 The approval is used under another request's identity | 1 UnitTest |
| HM-11 X-05 reverted: `Program.Main` back on `app.RunAsync()` | 3 IntegrationTests (`StartupFailureReportingTests`, the delayed-attachment rows) |
| HM-12 Separation of duties removed | 2 IntegrationTests (`ToolApprovalPipelineTests`) |
| HM-13 The approval endpoints accept `tool:execute` instead of `agent:approve` | 15 ApiTests (`ToolApprovalEndpointTests`) |
| HM-14 A decision whose recording failed is not withdrawn | 2 UnitTests (`DecideToolApprovalUseCaseTests`) |
| HM-15 An analysis is recorded for another client | 1 UnitTest, 7 ApiTests |
| HM-16 A decision takes effect before it is recorded (D-22 reverted) | 1 UnitTest (`…WhileTheApprovalIsBeingRecorded…`) |
| FM-01 The approval panel offers Approve / Deny for every status | 6 of 10 `ApprovalsPanel.test.tsx` |
| FM-02 An unknown approval status counts as pending | `ApprovalsPanel.test.tsx`, `approvals.test.ts` |
| FM-03 The approved headline follows the person's answer, not the gateway's confirmed run | `AttackLabPage.test.tsx` |
| FM-04 The decision request carries a body | `runScenario.test.ts`, `ApprovalsPanel.test.tsx`, `AttackLabPage.test.tsx` (5) |
| FM-05 Any refused decision (403, 500) is shown as a denial | `runScenario.test.ts`, `AttackLabPage.test.tsx` (4) |
| FM-06 The held call leaves the analysis's trace | `runScenario.test.ts`, `AttackLabPage.test.tsx` |
| FM-07 The export does not know the approval outcomes (T-09 reverted) | `report.test.ts` |
| FM-08 An approval run always "matches" its intent | `evidence.test.ts` |
| FM-09 A tool counts as run when the final response only claims `executed` | `AttackLabPage.test.tsx` |
| FM-10 The approval card states a fixed input decision (T-09 reverted) | `evidence.test.ts` |
| FM-11 A 403 on approval is explained as the generic agent error | `approvals.test.ts`, `ApprovalsPanel.test.tsx` |
| FM-12 The presented call drops the approval ID | `runScenario.test.ts`, `AttackLabPage.test.tsx` |

Not rerun: the M8, M10, M11 and M12 scopes. M13 changed files in them: `ToolGateway.cs`, `ToolGatewayEvent.cs` and
`ExecutionGrantAuthority.cs` are in an M13 scope above; `AnalyzeInputUseCase` and `AuthorizeAgentActionUseCase` changed only
in calling `EventSinks` (in the application scope, every mutant killed) and were not rerun.

### Milestone 12: Attack Lab, activity summary, D-21 (2026-10-07)

One focused Stryker scope for the new backend logic (`tests/mutation/stryker-attacklab-application.json`: the summary use
case and `ToolGateway.cs`, whose failure path changed for D-21), run against UnitTests. The console's Attack Lab, its
security operations section and the Activity kind badge are TypeScript, outside Stryker.NET: they were checked with
hand-applied mutants.

| Scope (config) | Code mutated | Tests | Mutants created | Valid | Detected | Survived | Mutation score | First run |
|---|---|---|---|---|---|---|---|---|
| `stryker-attacklab-application` | `ActivitySummaryUseCase` (13 valid), `ToolGateway` (23 valid) | UnitTests | 91 | 36 | 31 | 5 | **86.11%** (summary 100%) | 83.33% |

| Category | Count | Mutants | Why |
|---|---|---|---|
| a. Real gap | 0 left (1 closed) | `Kind == InputAnalysis` → `!=` in the summary: the test history held three inputs and three other records, so both comparisons counted 3 | Test data changed so every count differs from its complement (`ActivitySummaryUseCaseTests.ExecuteAsync_CountsEveryKindAndDecision_AsTheRecordsHoldThem`); killed in the final run and by a hand mutant |
| b. Equivalent | 5 | Internal exception messages in `ToolGateway` (unvalidated request, unknown gateway identity, duplicate argument policies, the aggregate of a tool failure and a recording failure, sink failures) | Classified the same way in M11; exception messages never reach a client |

**Hand-applied mutants (Milestone 12).** Same procedure as M11 (hash, mutate, rebuild without incremental build or rerun
Vitest, restore, check byte-identical). All 33 compiled and were killed; 3 frontend mutants survived the first round and
were real gaps, each closed by a test:

| Mutant | Tests that failed |
|---|---|
| Summary counts inputs with an inverted comparison | 1 of 6 `ActivitySummaryUseCaseTests` |
| Summary counts any tool call as executed | 2 of 6 |
| Summary reads a page of 100 instead of the whole history | 1 of 6 |
| D-21 reverted: the failure is recorded with the request's token | 1 of 37 `ToolGatewayTests` |
| D-21 reverted: a cancellation is not recorded as a failure | 2 of 37 `ToolGatewayTests` |
| Console, decision mapping (M01–M03): inherited lookup, unknown decision echoed, unknown decision shown as a known Allow | `evidence.test.ts`, `AttackLabPage.test.tsx` |
| Console, scores and execution status (M04–M06, M10): score bound, an input run counted as executed, an accepted replay not counted, the trail saying "ran" regardless | `evidence.test.ts` |
| Console, intent comparison (M07–M09): always "matches", a run of another scenario compared, a replay matching without a rejection | `evidence.test.ts`, `AttackLabPage.test.tsx` |
| Console, privacy filtering of the export (M11–M16, M25): unknown names copied, finding code unanchored, identifier of any text, `toolRan` from the flag alone, the policy reason text added, a pass field, the raw runs exported | `report.test.ts`, `AttackLabPage.test.tsx` (M12 and M14 survived the first round: closed by a code that only contains a valid code and by `executed: true` with another outcome) |
| Console, response handling and routing (M17–M23): any 4xx called a rejection, every 400 called a contract rejection, a scenario ID sent with a tool call, the replay without an execution ID, a failed second request thrown away, a case-insensitive scenario lookup, the error card of the wrong kind | `runScenario.test.ts`, `scenarios.test.ts`, `AttackLabPage.test.tsx` |
| Console, page state (M24): the latest run shown for whichever scenario is selected | `AttackLabPage.test.tsx` (survived the first round: closed by `shows each scenario only its own result`) |
| Console, security operations and Activity (M26–M28): negative counts accepted, an empty history shown as zeros, an unknown activity kind echoed | `SecurityOperations.test.tsx`, `ActivityPage.test.tsx` |

Not rerun: the M8, M10 and M11 scopes. M12 changed no file in them except `ToolGateway.cs` (one `catch`), which is in
the scope above.

### Milestone 11: tool gateway (2026-10-07)

Five focused scopes (`tests/mutation/stryker-gateway-*.json`), one test project per run. "First run" is before the gap
tests; the final run follows the tests added for the real gaps it found (T-07). Numbers computed from the Stryker JSON
reports; the API scope was run once.

| Scope (config) | Code mutated | Tests | Mutants created | Valid | Detected | Survived | No coverage | Mutation score | Covered-code score | First run |
|---|---|---|---|---|---|---|---|---|---|---|
| `stryker-gateway-security` | `Security/ToolGateway` (execution authority, argument policy) | SecurityTests | 111 | 73 | 64 | 7 | 2 | **87.67%** | 90.14% | 86.30% |
| `stryker-gateway-domain` | grant and scope, outcomes, tool types, `ToolGatewayEvent`, `AgentProfile` | UnitTests | 182 | 129 | 106 (1 timeout) | 23 | 0 | **82.17%** | 82.17% | 80.31% |
| `stryker-gateway-application` | gateway use case, request and validator, port result types, activity record, recorder, query mapping | UnitTests | 147 | 78 | 67 | 11 | 0 | **85.90%** | 85.90% | 75.64% |
| `stryker-gateway-infrastructure` | `KnowledgeLookupTool`, `LoggingToolGatewayEventSink`, `Infrastructure/Agents` | UnitTests | 206 | 66 | 56 | 10 | 0 | **84.85%** | 84.85% | 81.82% |
| `stryker-gateway-api` | `AgentToolsController`, `Permissions`, `ApiClientRegistry` | ApiTests | 102 | 5 | 3 | 1 | 1 | **60.00%** | 75.00% | (one run) |
| **M11 total** | | | 748 | 351 | 296 | 52 | 3 | **84.33%** | 85.06% | 80.52% |

"Valid" excludes mutants that do not compile and those Stryker ignores (static fields, attributes, the controller's
expression body). The API scope has few valid mutants because the controller is one expression and the permission and
policy names are constants; its behaviour is covered by the hand-applied mutants below.

**Every one of the 55 undetected mutants, classified.**

| Category | Count | Mutants | Why |
|---|---|---|---|
| a. Real gap | 0 left (13 closed) | First runs: the authority's own null guard on `Issue`; `Refused` without a verdict and the exact exception for a non-refusal outcome; the policy lookup's `&&` → `||`; the undefined-code guards and `IsAccepted` / `Executed` of the two port result types (4); the three 422 format messages; the sink's logger and entry null guards (2) | Each closed by a focused test (T-07) that kills it in the final run |
| b. Equivalent | 42 | Internal exception messages (Security 2, Domain 20, Application 9, Infrastructure 1); the signature length check and the two `catch` blocks whose removal returns the same `null`; `leaveOpen: false` (`MemoryStream.ToArray` works after disposal); the payload's context label (unobservable with a random per-process key); the metric's unit and description; the sink's early return (the generated logger checks the level again); `Prepend` → `Append` for the dataset's aliases (same keys); `key.Length > 0` → `>= 0` (unreachable after `Trim`) | No observable behaviour changes; exception messages never reach a client |
| c. Redundant | 10 | Null guards whose removal makes the next call throw the same `ArgumentNullException` (Domain 3, Application 2, Infrastructure 4 incl. `IMeterFactory.Create`, `ApiClientRegistry` constructor 1) | Only a programming error's stack changes |
| c. Unreachable | 3 | A second issue of the same UUIDv7 (2, no coverage); `ApiClientRegistry`'s message for an unvalidated hash (no coverage, pre-M10) | Cannot happen; startup validation comes first |

Pre-existing lines in mutated files (`AgentProfile`, `ListActivityUseCase`, `SecurityActivityRecord`,
`ConfiguredAgentDirectory`, `ApiClientRegistry`) account for 11 of the 55 and were classified the same way in M10.

**Hand-applied mutants (Milestone 11).** For what Stryker cannot isolate (one fluent policy chain, attributes, DI wiring,
the audit-level check, the frontend), each file was hashed, mutated, rebuilt without incremental build, tested, restored
and checked byte-identical. All 12 compiled and were killed:

| Mutant | Tests that failed |
|---|---|
| `ToolExecute` policy requires `agent:authorize` | 109 of 121 gateway ApiTests |
| The gateway controller declares the `AgentAuthorize` policy | 102 of 108 `ToolGatewayEndpointTests` |
| The client registry counts `agent:authorize` clients as gateway clients | 3 of 20 `ToolGatewayPipelineTests` |
| The gateway lets a Review through (only Block stops it) | 3 of 36 `ToolGatewayTests` |
| The gateway trusts a directory that answers for another caller | 1 of 36 `ToolGatewayTests` |
| The execution authority issues a grant without asking the boundary | 10 of 26 `ExecutionGrantAuthorityTests` |
| The activity recorder records every stage but the request | 1 of 12 `ToolGatewayActivityTests` |
| The audit-level startup check ignores the gateway sink | 1 of 20 `ToolGatewayPipelineTests` |
| The tool is also registered as itself (resolvable around the authority) | 1 of 20 `ToolGatewayPipelineTests` |
| Console: a tool counts as run without the `executed` flag | 3 of 18 Vitest tests (gateway model and preview) |
| Console: Activity shows a tool as run from the outcome alone | 1 of 8 `ActivityToolExecution.test.tsx` |
| Console: an unknown outcome is echoed | 3 of 26 Vitest tests |

Not rerun: the M8 and M10 scopes. M11 changed M10 files only additively (`AgentProfile.GatewayClient`, one catalogue entry,
`IAgentDirectory.FindByGatewayClient`, the directory validator's gateway rules, the activity record's new kind), and those
lines are in the gateway scopes above.

### Milestone 10: agent action authorization (2026-10-07)

Five focused scopes, one test project per run (T-02). "Before the gap tests" is the first run; the final run follows the
tests added for the real gaps it found (T-06). Every number below was computed from the Stryker JSON reports.

| Scope (config) | Code mutated | Tests | Mutants created | Valid | Killed | Survived | No coverage | Mutation score | Covered-code score | Before the gap tests |
|---|---|---|---|---|---|---|---|---|---|---|
| `stryker-agent-security` | `Security/Agents` (classifier, policy, authorizer, catalogue) | SecurityTests | 140 | 116 | 111 | 5 | 0 | **95.69%** | 95.69% | 93.10% |
| `stryker-agent-domain` | `Domain/Agents`, `AgentActionEvent` | UnitTests | 149 | 117 | 96 | 21 | 0 | **82.05%** | 82.05% | (one run) |
| `stryker-agent-application` | `Application/Agents`, activity record, recorder, query mapping | UnitTests | 72 | 50 | 43 | 7 | 0 | **86.00%** | 86.00% | 78.00% |
| `stryker-agent-infrastructure` | `Infrastructure/Agents`, `LoggingAgentActionEventSink` | UnitTests | 58 | 41 | 32 | 9 | 0 | **78.05%** | 78.05% | 70.73% |
| `stryker-agent-api` | `Api/Agents`, `Auth/Permissions`, `AuthorizationPolicies`, `AuthSetup`, `ApiClientRegistry` | ApiTests | 27 | 18 | 11 | 6 | 1 | **61.11%** | 64.71% | (one run) |
| **M10 total** | | | 446 | 342 | 293 | 48 | 1 | **85.67%** | 85.92% | |

No timeouts and no wall-clock tests are involved: the agent code has no time-dependent logic.

**Every one of the 49 undetected mutants, classified.**

| Category | Count | Mutants | Why |
|---|---|---|---|
| a. Real gap | 0 left (10 closed) | First runs: catalogue null guards (3), the four 422 format messages (4), the directory validator's `continue` (it kept invalid agent IDs out of later messages), `Any` → `All` on bound clients, the invalid-agent-ID message | Each closed by a focused test (T-06) that kills it in the final run |
| b. Equivalent | 31 | Internal exception messages (Security 4, Domain 17, Application 3); `effectLevel > level` → `>=` (assigning an equal level); `Length > 0` → `>= 0` and `separator > 0` → `>= 0` in `AgentIdentifiers` (an empty name part still fails the next check); the metric's unit and description; the sink's early return when the level is disabled (the generated logger checks the level again); `app.UseAuthentication()` removed (ASP.NET Core adds the middleware itself, as classified in M8) | No observable behaviour changes; exception messages never reach a client (Problem Details carry none) |
| c. Redundant | 13 | Argument null guards whose removal makes the next statement throw for the same null (Domain 2, Application 4, Infrastructure 6, `ApiClientRegistry` constructor 1) | Only the exception type of a programming error changes; still fail closed |
| c. Unreachable | 1 | `ApiClientRegistry`: the message for an unvalidated hash (no coverage) | Startup validation rejects such a hash first |
| d. Tooling limitation | 4 | `AuthSetup`: validator registration, the client log-context middleware and its two branches | Pre-M10 code that only IntegrationTests observe (startup validation, log properties). M8's merged API boundary scope kills them with IntegrationTests (T-02); the integration run of that scope was not repeated in M10 |

**Hand-applied mutants (Milestone 10).** For behaviour Stryker cannot isolate (one fluent policy chain, attributes,
the frontend), each file was hashed, mutated, rebuilt without incremental build, tested, restored and checked
byte-identical. All 10 were killed:

| Mutant | Tests that failed |
|---|---|
| `AgentAuthorize` policy requires `firewall:analyze` | 56 of 61 `AgentActionAuthorizeEndpointTests` |
| Controller loses its permission policy (`[Authorize]` only) | 4 of 61 `AgentActionAuthorizeEndpointTests` (403 rows, endpoint inventory) |
| Bindable clients are the firewall clients | 1 of 21 `AgentActionPipelineTests` (startup validation) |
| Use case takes a fixed caller instead of the authenticated client | 15 of 61 `AgentActionAuthorizeEndpointTests` (the first form did not compile and proved nothing; it was redone) |
| Use case stops at the first failing sink | 2 of 14 `AuthorizeAgentActionUseCaseTests` |
| Use case swallows sink failures | 2 of 14 `AuthorizeAgentActionUseCaseTests` |
| Activity keeps a claimed capability the catalogue does not know | 1 of 61 `AgentActionAuthorizeEndpointTests` (made-up names recorded as null) |
| Audit-level startup check ignores the agent sink | 1 of 21 `AgentActionPipelineTests` |
| Console shows an unknown agent-action decision as Allow | 10 of 48 Vitest tests in `features/agents` |
| Activity echoes the raw agent-action reason | 3 of 55 Vitest tests in `features/activity` |

### Milestone 8 scopes

Stryker.NET 5.0.0 (ADR 0018), run on 2026-10-01 after the gap tests below were added. "Valid" mutants exclude those that
do not compile and those Stryker filters out (outside the mutate filter, or duplicates inside a block already mutated).
The mutation score is detected ÷ valid. The covered-code score leaves out mutants that no test executes.

| Scope | Code mutated | Tests | Mutants created | Valid | Killed | Timeout | Survived | No coverage | Mutation score | Covered-code score | Before the gap tests |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Security | Security project (all files but `DependencyInjection.cs`) | SecurityTests | 910 | 640 | 523 | 45 | 65 | 7 | **88.75%** | 89.73% | 84.22% (first run) |
| AI capacity and circuit breaker | `Infrastructure/AiCapacity` | UnitTests | 595 | 428 | 383 | 1 | 42 | 2 | **89.72%** | 90.14% | 82.48% (first run) |
| API boundary | `Api/Auth`, `Api/RateLimiting` | ApiTests + IntegrationTests (two runs, merged) | 258 | 133 | 112 | 1 | 15 | 5 | **84.96%** | 88.28% | 49.62% (first run, ApiTests only) |
| **All scopes** | | | 1,763 | 1,201 | 1,018 | 47 | 122 | 14 | **88.68%** | 89.72% | |

The API boundary scope is run once per test project and the two reports are merged (`tests/mutation/merge-reports.mjs`).
A single run with both test projects misreported mutants (finding T-02 in the defect matrix).

**Wall-clock caveat (Security scope).** 65 of the Security kills rest only on tests with a wall-clock budget
(`ObfuscationBoundsTests`, the maximum-length robustness properties). Some are genuine: a mutant that makes a loop
endless or much slower fails those tests by design. Others are noise from Stryker's CPU load; 3 of them, for example,
are in the AI stage, which those tests do not run. Between runs a handful of mutants moved between "killed" and
"survived" for this reason. If every one of those 65 kills is discounted, the Security score is 78.59%. The true figure
lies between that and the reported score. The AI capacity tests use a manual clock. In the API boundary scope, the
two kills by tests that involve real time (`Retry-After`, window refill) fail on what the mutant does (a wrong
`Retry-After`, a refused one-second window), not on load.

### Surviving mutants

Every mutant the final runs did not detect, in one of four categories. **a. Real, accepted**: the mutant changes
behaviour, but only in a way that does not matter for security (wording, metric metadata), with the reason given.
**b. Equivalent**: no input can tell the mutant from the original. **c. Redundant or unreachable**: the code guards
a state the rest of the system already excludes. **d. Tooling limitation**: none among the survivors. The tooling
limits are listed below the tables. No survivor is a real gap left open: each one found was closed (next section).

**Security** (72 not detected)

| Category | Mutants | Reason |
|---|---|---|
| a. Real, accepted | 1: ContentDecoders:110 | A run mixing both Base64 alphabets is deliberately not decoded (paths, identifiers). The mutant decodes more, and decoding alone never creates a finding |
| a. Real, accepted | 3: AiFailurePolicy:58, CharacterUnmasking:147, SeverityRiskEngine:49 | Message text of an exception that signals a programming error; never reaches a client (Problem Details carry no exception text) |
| b. Equivalent | 1: ObfuscationDetector:333 | A High rule raised to at least High stays High |
| b. Equivalent | 1: ContentDecoders:103 | A length of 4n+1 cannot be valid Base64; the decoder rejects it later anyway |
| b. Equivalent | 1: AiAssistedAnalysis:110 | A probe timeout equal to the stage timeout gives the same bound either way |
| b. Equivalent | 1: CharacterUnmasking:265 | A run that qualifies always has gaps, so the sequence is never empty |
| b. Equivalent | 1: ObfuscationDetector:177 | Cache of the baseline counts: recomputing gives the same counts |
| b. Equivalent | 6: ObfuscationDetector:76, ObfuscationDetector:79, ObfuscationDetector:83, ObfuscationDetector:86, ObfuscationDetector:90, ObfuscationDetector:93 | Code and description of the compact rules are never read: their findings use the obfuscation code and description |
| b. Equivalent | 1: FindingAggregator:116 | Fast path of the evidence comparer: comparing an evidence with itself field by field also gives 0 |
| b. Equivalent | 3: CharacterUnmasking:157, CharacterUnmasking:162, CharacterUnmasking:166 | Fast path of the leetspeak pass: running it on a word without substitutes leaves the word unchanged |
| b. Equivalent | 2: CharacterUnmasking:66, CharacterUnmasking:88 | Fast path: ASCII text has no marks to remove; text without look-alikes folds to itself |
| b. Equivalent | 1: ObfuscationDetector:128 | Fast path: an empty input produces no views and no findings |
| b. Equivalent | 1: HiddenCharacterDecoding:57 | Fast path: text without tag characters or selectors yields no hidden runs, so the full scan also returns null |
| b. Equivalent | 2: FindingAggregator:37, FindingAggregator:53 | Fast path: the general code returns an equal result for an empty list or a single finding |
| b. Equivalent | 2: ContentDecoders:76, ContentDecoders:93 | Fast path: without an escape or "&" the decoder returns the text unchanged, which is reported as "no change" |
| b. Equivalent | 1: SensitiveDataRedactor:66 | Null and empty both give an empty result |
| b. Equivalent | 1: ContentDecoders:175 | Pre-check only: the decoder leaves invalid escapes unchanged and reports "no change" |
| b. Equivalent | 2: HiddenCharacterDecoding:80, HiddenCharacterDecoding:120 | Reading past the end returns "not hidden"; the code point of a non-hidden character is never used |
| b. Equivalent | 1: ContentDecoders:36 | Removing the continue after a non-Base64 character only re-enters the same scan at the next character |
| b. Equivalent | 2: ContentDecoders:147, ContentDecoders:148 | Returning buffers to the pool affects reuse, not results |
| b. Equivalent | 1: ContentDecoders:121 | Size of a pooled buffer, an upper bound only |
| b. Equivalent | 4: SensitiveDataRedactor:87 ×4 | Stack or heap buffer for a property name: same result (names are developer-chosen and short) |
| b. Equivalent | 3: HiddenCharacterDecoding:84, HiddenCharacterDecoding:135, HiddenCharacterDecoding:136 | The (char)/(byte) cast keeps the low bits, and twice the offset (0xE0000, 0xFE00, 0xE0100) has none there: + and - give the same value |
| b. Equivalent | 1: CharacterUnmasking:235 | With no separator between two characters the next one cannot be a single spaced character, so ">=" adds nothing |
| c. Redundant or unreachable | 1: ContentDecoders:164 | A Base64 segment of at least 16 characters never decodes to an empty string |
| c. Redundant or unreachable | 15: AiInputTokenEstimate:34, AiResponseValidator:49, AiResponseValidator:50, IAiDisclosurePolicy:32, RedactingAiDisclosurePolicy:26, CharacterUnmasking:103, CharacterUnmasking:143, ContentDecoders:26, HiddenCharacterDecoding:53, ObfuscationDetector:102, ObfuscationDetector:103, ObfuscationDetector:124, PatternThreatDetector:36, PatternThreatDetector:51, RiskThresholdPolicyEngine:33 | Argument guard on a constructor or method that DI and the pipeline never call with null or a negative value; removing it only changes which exception a programming error raises |
| c. Redundant or unreachable | 2: AiAssistedAnalysis:168, AiAssistedAnalysis:170 (no coverage) | Every AI failure maps to the one handling (Review); the other branch cannot be reached |
| c. Redundant or unreachable | 5: FindingAggregator:120, FindingAggregator:122 (no coverage) ×4 | Null branches of the evidence comparer: a finding cannot be built without evidence |
| c. Redundant or unreachable | 2: ObfuscationDetector:302 ×2 | Pre-check before normalisation; the same limit is enforced again on the normalised view, which is what is inspected. It differs only for input far beyond the API limit |
| c. Redundant or unreachable | 1: SensitiveDataRedactor:81 (no coverage) | Regex-timeout fallback: NonBacktracking patterns run in linear time and cannot be made to time out by a test |
| c. Redundant or unreachable | 2: ObfuscationDetector:315 ×2 | The view budget (16) equals the most views one input can produce (2 hidden + 2 unmasked + 3 + 9 decoded), so it is never exhausted |
| c. Redundant or unreachable | 1: SeverityRiskEngine:58 (no coverage) | Unknown-level branch after BaseScoreFor has already rejected the same severity |

**AI capacity and circuit breaker** (44 not detected)

| Category | Mutants | Reason |
|---|---|---|
| a. Real, accepted | 14: InMemoryAiCapacityGate:90, InMemoryAiCapacityGate:91, InMemoryAiCapacityGate:94, InMemoryAiCapacityGate:95, InMemoryAiCapacityGate:98, InMemoryAiCapacityGate:99, InMemoryAiCircuitBreaker:96 ×2, InMemoryAiCircuitBreaker:97 ×2, InMemoryAiCircuitBreaker:98 ×2, InMemoryAiCircuitBreaker:99 ×2 | Unit and description metadata of metric instruments; names, tags and values are asserted |
| b. Equivalent | 2: InMemoryAiCircuitBreaker:223, InMemoryAiCircuitBreaker:269 | A probe in flight implies HalfOpen and a permit settles once, so the rewritten condition never differs |
| b. Equivalent | 3: AiCapacityOptionsValidator:64, AiCapacityOptionsValidator:69, AiCapacityOptionsValidator:74 | A zero guarantee is already rejected, and zero times any number of clients never exceeds a positive budget |
| b. Equivalent | 1: InMemoryAiCapacityGate:140 (no coverage) | Any client ID that is not configured is refused the same way |
| b. Equivalent | 1: InMemoryAiCircuitBreaker:292 | At most one transition happens per call, so the list never already holds one |
| b. Equivalent | 2: InMemoryAiCircuitBreaker:256, InMemoryAiCircuitBreaker:285 | Each of the two generation increments (on opening, on closing) alone separates the periods; removing one changes nothing observable |
| b. Equivalent | 1: InMemoryAiCircuitBreaker:148 | Probe IDs only need to be unique; counting down keeps them unique |
| c. Redundant or unreachable | 14: AiCapacityOptionsValidator:21, AiCircuitBreakerOptions:54, InMemoryAiCapacityGate:62, InMemoryAiCapacityGate:63, InMemoryAiCapacityGate:64, InMemoryAiCapacityGate:65, InMemoryAiCapacityGate:66, InMemoryAiCapacityGate:130, InMemoryAiCircuitBreaker:79, InMemoryAiCircuitBreaker:80, InMemoryAiCircuitBreaker:81, InMemoryAiCircuitBreaker:82, RequestBudget:58, RequestBudget:59 | Argument guard on a constructor or method that DI and the pipeline never call with null or a negative value; removing it only changes which exception a programming error raises |
| c. Redundant or unreachable | 1: InMemoryAiCircuitBreaker:89 (no coverage) | Breaker built without Enabled: the validator refuses that whenever AI is on, and with AI off the breaker is never used |
| c. Redundant or unreachable | 1: InMemoryAiCapacityGate:131 | Duplicate of the budget's own negative-amount guard (pinned by Budget_NegativeAmount_IsABug_EvenWhenTheGateIsBypassed) |
| c. Redundant or unreachable | 4: InMemoryAiCapacityGate:78, InMemoryAiCapacityGate:82, InMemoryAiCircuitBreaker:91, InMemoryAiCircuitBreaker:93 | Overflow check on window lengths from validated settings and the clock frequency; cannot overflow |

**API boundary** (20 not detected)

| Category | Mutants | Reason |
|---|---|---|
| a. Real, accepted | 2: RateLimitingSetup:98, RateLimitingSetup:110 | Wording only: the "(anonymous)" placeholder in the rate-limit log, and the 429 detail text. Status, errorCode, Retry-After and log fields are asserted |
| b. Equivalent | 1: AuthSetup:50 | ASP.NET Core adds the authentication middleware itself when the app does not; every authentication test still passes |
| b. Equivalent | 1: ApiAuthenticationOptions:53 | Continuing after an invalid client ID only adds further failure messages; startup fails either way |
| b. Equivalent | 1: ApiAuthenticationOptions:86 | Fail with an empty list does not stop startup, and the list is empty exactly when the original returns Success (finding T-03) |
| b. Equivalent | 1: ApiKeyAuthenticationHandler:54 | Order of the permission claims; authorization looks claims up by value |
| b. Equivalent | 1: RateLimitingSetup:63 | Partition key of the no-limit partition used when rate limiting is off; any key behaves the same |
| b. Equivalent | 3: RateLimitingSetup:68, RateLimitingSetup:69 ×2 | Prefix or fallback text of the anonymous partition key; partitions stay distinct (client IDs cannot contain ":") |
| b. Equivalent | 1: ApiKeys:59 (no coverage) | Stryker's block removal returns null, the same value the catch block returns |
| b. Equivalent | 1: RateLimitingSetup:77 | The partitioned limiter replenishes partitions that do not replenish themselves, so the window still refills (Window_RefillsOnceItEnds_SoALimitedClientIsServedAgain passes either way) |
| c. Redundant or unreachable | 3: ApiAuthenticationOptions:43, ApiClientRegistry:18, ApiKeys:42 | Argument guard on a constructor or method that DI and the pipeline never call with null or a negative value; removing it only changes which exception a programming error raises |
| c. Redundant or unreachable | 4: ApiClientRegistry:23 (no coverage), ApiKeyAuthenticationHandler:72 (no coverage), HttpCallerContext:14 (no coverage), RateLimitingSetup:95 (no coverage) | Fallback for a state the pipeline excludes (validated hashes, authenticated callers, endpoints with a policy) |
| c. Redundant or unreachable | 1: RateLimitingSetup:111 | The Problem Details customiser adds the same errorCode to every response |

Tooling limitations (not counted as survivors): Stryker could not compile 220 mutants (Security 171, mostly inside
generated regex code and pattern expressions; AI capacity 38; API 11), and they are left out of every score. In the
Security scope, kills and timeouts that rest on wall-clock budget tests vary between runs (see the caveat above). The
API boundary scope must run once per test project (T-02).

### Gaps closed in Milestone 8

Each test below (31 mutants of production code and 8 of the console) was shown to fail against its mutant, applied by hand to an otherwise unchanged build. The file was then
restored and its hash checked. Two mutants that our analyzers reject (CA1805, CS0162) were applied with warnings-as-errors
relaxed for that one build.

| Area | Mutant (what the code got wrong) | Test that now fails |
|---|---|---|
| Client-ID validation | Maximum length exclusive (64 rejected) | `SecurityConfigurationTests.ClientIdLength_IsLimitedTo64Characters_Inclusive` |
| Client-ID validation | An empty client ID accepted (bindable, e.g. `Authentication__Clients____KeyHashes__0`) | `InvalidSecurityConfiguration_FailsAtStartup` (empty-ID row) |
| Validation messages | A failure message emptied or no longer naming its setting (authentication hashes, `RateLimiting:Firewall`, `RateLimiting:Enabled`) | `InvalidSecurityConfiguration_FailsAtStartup`, `RateLimitingDisabled_OutsideDevelopment_FailsAtStartup` (assert the message names the setting and never repeats a hash) |
| Rate-limit options | `WindowSeconds` or `QueueLimit` maximum exclusive | `RateLimitSettings_ExactlyAtTheirMaximum_AreAccepted` |
| Rate-limit options | Rate limiting off when the setting is missing | `RateLimitingTests.Options_LeftUnconfigured_KeepRateLimitingOn` |
| Key format | Length **or** characters valid instead of both; minimum **or** maximum length; the handler treating a single malformed key as well formed | `AccessControlLoggingTests.MalformedKey_IsLoggedAsMalformed_NotAsUnknown` |
| Key format | Maximum key length exclusive | `AuthenticationTests.Analyze_ConfiguredKeyAtTheLengthLimits_IsAcceptedOnlyWithinThem` |
| Rate-limit partitions | Anonymous requests pooled into one partition; remote address ignored | `RateLimitingTests.AnonymousRequests_ArePartitionedByRemoteAddress_NotPooled` |
| Circuit breaker | A late report from an expired probe counted again; a released probe not counted | `InMemoryAiCircuitBreakerTests.Metrics_EveryProbeHasOneResult_AReleasedProbeIsAbandoned_AndALateReportIsNotCountedAgain` |
| Circuit breaker | A probe outcome that says nothing about the provider labelled "succeeded", or closing the circuit | `Probe_ReportedWithAnOutcomeThatSaysNothingAboutTheProvider_FreesTheSlot_WithoutChangingState` |
| Circuit breaker | The expired-probe transition logged without its reason | `Transitions_AProbeThatExpires_IsLoggedWithTheReasonProbeExpired` |
| Token budget | The budget accepting a negative amount | `AiInputTokenBudgetTests.Budget_NegativeAmount_IsABug_EvenWhenTheGateIsBypassed` |
| Fusion | Match count ignored between duplicates of one rule (result followed the input order) | `FindingAggregatorTests.Aggregate_DuplicatesOfOneRule_KeepTheStrongestObservation_AndOrderTheRestByMatchCount_InEveryInputOrder` |
| Base64 decoder | A third `=` counted as padding, so the segment before it was no longer decoded | `ContentDecodersTests.DecodeBase64Segments_PaddingVariants_AreDecoded` (surplus-padding row) |
| Spacing | The documented tie-breaks between equally common gaps reversed (longer first, ordinally larger first) | `CharacterUnmaskingTests.CollapseSpacing_JoinsSpacedOutCharacters` (two tie rows) |
| Nested decoding | What a decoder reveals on its own added to, not subtracted from, the plain-text matches, hiding a nested attack's finding | `ObfuscationDetectorTests.Detect_NestedEncoding_BesideTheSameAttackInPlainText_AndAnUnrelatedPercentEscape_IsReported` |
| Redaction | The exact secret names `pin`, `otp`, `ssn` no longer masked | `SensitiveDataRedactorTests.IsSensitiveKey_DetectsSecretNames` (three rows) |
| Fusion | Fused duplicates keep the lowest severity | `DecisionCoreBoundaryTests.EveryMultiset_ThroughTheAggregator_TheMostSevereFindingDecides_SoMediumIsNeverAllowedAndHighIsAlwaysBlocked` |
| Risk | An undefined severity scored as Low | `UndefinedSeverity_IsRejectedByTheFindingAndTheRiskEngine_NeverScoredAsLow` |
| Risk | Findings with an unrecognised code ignored | `FindingWithACodeNothingKnows_InEveryCategory_AtZeroConfidence_IsDecidedByItsSeverity_NeverIgnored` |
| Policy | Many findings turning a Review into an Allow | `AddingAFindingOfAnySeverity_ToEveryMultiset_NeverLowersTheScoreLevelOrDecision` |
| Obfuscation | A view reported although it reveals nothing new | `DetectionRobustnessPropertyTests.Analyze_RandomStacksOfObfuscation_NeverThrow_StayWithinBudget_AndBenignTextIsNeverFlagged` |
| Console | Allow summary promising safety; AI safeguard not recognised; correlation ID not shown; stale result not marked | `AnalyzePage.test.tsx` (Allow, AI safeguard, technical details, out of date) |

Earlier in Milestone 8, the gap tests written after the first Stryker runs killed their mutants (shown by Stryker's
`killedBy` in the final runs). They cover the compact rule OB-C02, the spacing rule at exactly four letters and with several runs,
selectors at the start of the text and at the ends of both selector ranges, a decoded view exactly at the limit and
one character over it, the normaliser's last variation selector, the redactor's output format, a stray cancellation in
the AI stage, the aggregator's documented tie-breaks, the capacity and circuit validators at their limits, refusal-log
throttling, token-rejection metrics, the global budget cap, the probe start failing once, metric tags, the API key
length limits, `Retry-After` as the time left, and a window refilling.

## Coverage by security area

"Mutation" gives the Stryker score of the code behind the row (detected ÷ valid mutants, final run) and, where they
exist, the hand-made mutation checks recorded since Milestone 3: "mutant → n fail" means the named fault made n tests
fail. **Not in a mutation scope** means Stryker was not run on that code; hand-made checks are listed where they exist.

| # | Security area | Unit | Integration | HTTP | Mutation | Gap |
|---|---|---|---|---|---|---|
| 1 | Input normalisation (invisible characters, NFKC, U+FFFE) | `InputNormalizerTests`; `DetectionRobustnessPropertyTests` (malformed and random Unicode; U+FFFE raw and decoded) | — | Indirect: every analysis runs it; `AnalyzeEndpointTests.InputContainingUFFFE_IsAnalysed_AndDecidedLikeTheSameTextWithoutIt_D18`, `BenignInputContainingUFFFE_IsAllowed_WithoutAFindingOfItsOwn_D18` | Stryker 100.00% (19/19) before the D-18 change (not rerun); the 12 D-18 cases failed on the unfixed code | — (D-18 fixed 2026-10-01) |
| 2 | Plain-text detection (instruction override, role manipulation, secret extraction) | Detector tests, `AnalyzeInputUseCaseTests` | `FirewallCompositionTests` | `AnalyzeEndpointTests` | Stryker 94.29% (33/35); Scrutor `Skip` restored → 5 fail (D-01) | The tests prove the listed phrasings only (baseline recall 0.38) |
| 3 | Detector bounds (linear time, timeout, no input in findings) | `DetectorContractTests`, `ObfuscationBoundsTests`, robustness properties (32,000-character random input within 2 s) | — | `InputAtMaximumLength_IsAnalysed`, `DetectorFailure_Returns500WithoutLeakingInternals`, `MaximumLengthHostileInput_IsAnalysedInBoundedTime` | Covered by rows 2 and 4 | Time budgets are wall-clock and machine-dependent |
| 4 | Encoding obfuscation (Base64, percent, HTML; 2 layers) | `ContentDecodersTests`, `ObfuscationDetectorTests`, encoding-transparency and decoder-pair properties | — | `ObfuscationEndpointTests` | Stryker 83.73% (139/166) | Encodings that are not implemented are documented false negatives |
| 5 | Character disguises (look-alikes, accents, spacing, leetspeak) | `CharacterUnmaskingTests`, `ObfuscationDetectorTests`, stacked-obfuscation property | — | `ObfuscationEndpointTests.ObfuscatedInjection_IsBlocked` | Stryker 92.96% (132/142) | Substitution tables are heuristic |
| 6 | Hidden characters (tag characters, variation-selector runs) | `HiddenCharacterDecodingTests`, `HiddenCharacterDetectionTests`, hidden-text properties | `HiddenCharacterLoggingTests` | `HiddenCharacterEndpointTests` | Stryker 89.86% (62/69) | The AI stage never sees hidden runs (by design) |
| 7 | Obfuscation limits (uninspectable content → Review) | `ObfuscationDetectorTests` (incl. a decoded view exactly at the limit and one character over) | — | `ContentTooLargeToInspect_IsHeldForReview_NeverAllowedAndNeverTruncated` | In row 4 | — |
| 8 | Finding fusion (dedup, ordering) | `FindingAggregatorTests` (every permutation, documented tie-breaks), decision-core tests through fusion | `SecurityEventLoggingTests.FusedDuplicates_LogTheEvidenceOfEveryDuplicate` | — | Stryker 79.49% (31/39) | — |
| 9 | Risk scoring | `SeverityRiskEngineTests`, `RiskAssessmentTests`, `DecisionCoreBoundaryTests` (every multiset of up to six severities, exact caps) | — | `AnalyzeEndpointTests` | Stryker 75.00% (6/8) | Prototype scale, not calibrated |
| 10 | Policy (risk → Allow / Review / Block) | `RiskThresholdPolicyEngineTests`, `DecisionCoreBoundaryTests` (every score 0–100, both sides of each threshold, monotonicity) | — | `MediumRiskInput_Returns200WithReview`, `PromptInjection_Returns200WithBlock_NotAnHttpError` | Stryker 92.86% (13/14) | — |
| 11 | Use case orchestration and fail-closed stages | `AnalyzeInputUseCaseTests` | `AiAnalysisPipelineTests` | `DetectorFailure_Returns500WithoutLeakingInternals` | Not in a mutation scope; use case dropping AI findings → 1 Unit + 9 Integration fail | — |
| 12 | Audit / security events | `SecurityEventTests`, `AnalyzeInputUseCaseTests` (every sink, sink failures), `LoggingSecurityEventSinkTests` | `SecurityEventLoggingTests`, `SecurityConfigurationTests.SecurityEventsHiddenByTheLogLevel_*`, `ActivityPipelineTests.ActivityStoreFails_TheAuditLogStillRecordsTheBlock_AndTheCallerGetsNoDecision` | `ActivityEndpointTests.Analyze_ActivityHistoryFails_FailsClosedWith500AndNoDecision` | Not in a mutation scope; startup tests failed before the H-07 fix; stopping at the first failing sink → 2 Unit + 1 Integration fail; swallowing a sink failure → 2 Unit + 1 Integration + 2 HTTP fail | A sink failing inside Serilog loses entries silently |
| 13 | AI output validation | `AiStructuredOutputParserTests`, `AiResponseValidatorTests` | `AiAnalysisPipelineTests` | — | Validator: Stryker 96.49% (55/57); parser (AI project) not in a scope; confidence check weakened → 7 fail | Scripted answers only |
| 14 | AI failure policy and timeout | `AiFailurePolicyTests`, `AiAssistedAnalysisTests` | `AiAnalysisPipelineTests`, `GeminiProviderPipelineTests` | Integration over HTTP | Stryker 86.84% (33/38) | — |
| 15 | AI fusion with deterministic results | `AiFindingFusionTests`, `AnalyzeInputUseCaseTests` | `AiAnalysisPipelineTests`, `AiCapacityPipelineTests` | — | In rows 8–10 and 14 | No ceiling on AI-only severity (open policy decision) |
| 16 | AI disclosure (normalised, secrets masked, never truncated) | `RedactingAiDisclosurePolicyTests`, `SensitiveDataRedactorTests` | `GeminiProviderPipelineTests` | — | Stryker 86.54% (45/52) | No PII masking before disclosure |
| 17 | Gemini adapter | `GeminiSecurityAnalyzerTests`, `GeminiRequestTests`, `GeminiTokenEstimateTests`, `GeminiAiAnalysisStageTests` | `GeminiProviderPipelineTests`, `GeminiRedirectTests` | Integration over HTTP | Not in a mutation scope; 20+ hand-made checks recorded since Milestone 4 (SDK attempts, pinned endpoint, status mapping, response cap, redirects, exception text) | Real API only through the manual smoke script and the evaluation runner |
| 18 | AI capacity gate | `InMemoryAiCapacityGateTests`, `AiCapacityOptionsValidatorTests`, `AiInputTokenBudgetTests`, `AiCapacityStagePipelineTests` | `AiCapacityPipelineTests` | Integration over HTTP | Stryker 91.47% (236/258) | No load test |
| 19 | Circuit breaker | `InMemoryAiCircuitBreakerTests`, `AiCircuitBreakerOptionsValidatorTests`; Security `AiCircuitStageTests` | `AiCircuitBreakerPipelineTests` | Integration over HTTP | Stryker 87.06% (148/170) | Controlled interleavings, not load |
| 20 | Authentication (API keys) | — | `SecurityConfigurationTests`, `AccessControlLoggingTests` (no key logged; malformed vs unknown reason) | `AuthenticationTests`, `ProductionAuthenticationTests`, `KestrelBoundaryTests` | Stryker 85.90% (67/78) | — |
| 21 | Authorization (fallback policy, permission policies) | — | — | `AuthorizationTests` incl. the endpoint inventory | Stryker 100.00% (1/1); `[AllowAnonymous]` added → inventory test fails | — |
| 22 | Rate limiting | — | `AccessControlLoggingTests.RateLimited_*`, `SecurityConfigurationTests` (limits at and past their maximum) | `RateLimitingTests` (per client, per address for anonymous requests, exact `Retry-After`, refill, flood) | Stryker 83.33% (45/54) | Process-local only |
| 23 | CORS, security headers, Kestrel boundary | — | — | `CorsTests`, `SecurityHeadersTests`, `KestrelBoundaryTests` | Not in a mutation scope | — |
| 24 | Request contract (strict JSON, size limits, validation, correlation IDs) | `AnalyzeInputRequestValidatorTests` | `LoggingPipelineTests` | `JsonInputPolicyTests`, `RequestSizeLimitTests`, `AdversarialRequestTests`, `CorrelationIdTests` | Not in a mutation scope; 23 of 40 failed before the D-02 fix | — |
| 25 | Error handling and information leakage | `ResultTests`, `ErrorTests` | `HealthEndpointTests`, `GeminiProviderPipelineTests`, `LoggingPipelineTests` | `ErrorResponseContractTests`, `Response_NeverEchoesTheInput`, `Response_NeverRevealsRuleIdsDetectorsOrDecodedContent` | Not in a mutation scope; failed before the H-01/H-04 fixes | Unexpected exception text is logged with secrets masked, not proven free of input fragments |
| 26 | Log redaction | `SensitiveDataRedactorTests` | `LoggingPipelineTests` | — | Redactor in row 16; the Serilog enricher is not in a scope | Only the listed secret formats are masked |
| 27 | Composition (DI, startup validation) | `ConventionalRegistrationTests` | `CompositionTests`, `ConventionalResolutionTests`, `FirewallCompositionTests`, `SecurityConfigurationTests` | — | Scrutor `Skip` restored → 5 fail (D-01) | X-02 (one failure under parallel load, earlier milestone) |
| 28 | AI evaluation tooling | — | `AiEvaluationSetTests`, `EvaluationLogicTests`, `EvaluationRunnerTests` | — | Not in a mutation scope; 10 hand-made checks recorded (Milestone 7.1, final review) | D-14 has no test |
| 30 | Security activity history (metadata-only record, recording from the final decision, bounded store, read API, console) | `SecurityActivityRecordTests`, `SecurityActivityRecorderTests`, `ListActivityRequestValidatorTests`, `ListActivityUseCaseTests`, `InMemorySecurityActivityStoreTests`; Vitest `activity.test.ts`, `ActivityPage.test.tsx` | `ActivityPipelineTests` (incl. fake Gemini privacy), `FirewallCompositionTests` | `ActivityEndpointTests`, `ActivitySwaggerTests`, `RateLimitingTests.Activity_*`, `AuthorizationTests` inventory; browser checks (Activity section of `overview.check.mjs`) | Not in a mutation scope; hand-made: failures summarised as Completed → 12 Unit + 1 Integration fail; no page-size bound → 2 Unit + 2 HTTP fail; console echoing an unknown AI status → 10 Vitest fail; the two sink mutants in row 12 | Not durable, per process; offset paging over a live history; a reader sees every client's activity |
| 31 | Agent action authorization (names, catalogue, risk, policy, caller binding, recording, API, console preview) | `AgentIdentifierTests`, `AgentModelTests`, `AgentActionEventTests`, `AuthorizeAgentActionRequestValidatorTests`, `AuthorizeAgentActionUseCaseTests`, `AgentActionActivityTests`, `AgentDirectoryTests`, `LoggingAgentActionEventSinkTests`; Security: `ActionRiskClassifierTests` (2,047 combinations), `AgentActionPolicyTests` (1,024), `ReferenceToolCatalogTests`, `AgentActionAuthorizerTests`, `AgentAttackScenarioTests`; Vitest `presentation.test.ts`, `AgentSecurityPage.test.tsx`, agent rows in `ActivityPage.test.tsx` | `AgentActionPipelineTests` | `AgentActionAuthorizeEndpointTests`, `AgentActionSwaggerTests`, `RateLimitingTests.AgentAuthorization_*`; browser checks `agents.check.mjs` | Stryker 85.67% (293/342) over five focused scopes, every survivor classified; 10 hand-made mutants, all killed (section "Milestone 10") | Decision only: execution is not enforced; arguments not checked; input decision self-reported |
| 32 | Tool gateway (complete mediation, identity from the credential, argument policy, execution grants, stage-by-stage recording, console preview) | `ToolGatewayModelTests`, `ToolGatewayEventTests`, `ExecuteToolRequestValidatorTests`, `ToolGatewayTests`, `ToolGatewayResultTypesTests`, `ToolGatewayActivityTests`, `AgentGatewayIdentityTests`, `KnowledgeLookupToolTests`, `LoggingToolGatewayEventSinkTests`; Security `KnowledgeLookupArgumentPolicyTests`, `ExecutionGrantAuthorityTests`; Vitest `gateway.test.ts`, `ToolGatewayPreview.test.tsx`, `ActivityToolExecution.test.tsx` | `ToolGatewayPipelineTests` (complete mediation over every AgentShield type, audit stages, startup validation) | `ToolGatewayEndpointTests` (probe on every executor), `ToolGatewayRiskModelTests`, `ToolGatewaySwaggerTests`, a `RateLimitingTests` row; browser checks `agents.check.mjs` | Stryker 84.33% (296/351), 12 hand-applied mutants killed | One in-memory reference tool; grants per process |
| 29 | Console presentation and error display | Vitest: `decision.test.ts`, `findings.test.ts`, `errors.test.ts`, `retryAfter.test.ts`, `apiClient.test.ts`, `AnalyzePage.test.tsx` | — | Browser checks (on demand) | 8 hand-made mutants, all killed (decision tone, own-property lookup, `Retry-After` bound, input echo; Allow wording, AI safeguard, correlation ID, stale marker); no JavaScript mutation tool | Browser checks are not run automatically |

## Gaps, most important first

0. **Enforcement is proven for one tool only (Milestone 11).** For `knowledge.lookup` the tests show that no path
   inside AgentShield reaches the tool without an Allow, a validated call and a consumed grant (invariants 57–70). For
   every other tool AgentShield still only decides, so no test can show it is unreachable without an Allow.

1. **D-18 is fixed (2026-10-01).** Input containing U+FFFE, raw or produced by a decoder, is analysed instead of
   failing with 500. The Security mutation score was not rerun after the one-line change (the 12 regression cases
   failed on the unfixed code).
2. **Detection breadth is measured, not tested.** The tests prove the listed phrasings and encodings. Recall on the
   synthetic set is 0.38, and non-English and paraphrased attacks are not detected with AI off. More tests would not
   change that.
3. **Not in any mutation scope:** the use case, the Gemini adapter and AI parser, error handling, JSON input policy,
   CORS and headers, logging enrichers, the evaluation runner. They have hand-made mutation checks only.
4. **No frontend mutation tool.** The console tests were checked with 8 hand-made mutants. The browser checks run only
   on demand.
5. **Audit durability.** Audit is a log line only. A sink failing inside Serilog loses the entry (the metric still counts
   it).
6. **The real model is not tested by automated tests** (by design). The only real-model evidence is the M14-R2 evaluation: 81 of 87 completed
   evaluation analyses, which cannot be quoted as accuracy.
7. **Concurrency** is covered by controlled interleavings and one flood test, not by load or soak tests.
8. **Wall-clock budgets** in the robustness and bounds tests depend on the machine.
