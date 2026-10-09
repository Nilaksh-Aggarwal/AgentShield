# Tool gateway

The enforcement point for agent tool calls (Milestone 11): the agent asks AgentShield to run a tool action, and
AgentShield runs it **only on Allow**, or on a Review a person approved (Milestone 13, sections 16–18). Decision records:
[ADR 0021](../decisions/0021-tool-gateway-enforced-execution.md), [ADR 0023](../decisions/0023-human-approval-and-input-event-binding.md).
Guarantees and their evidence: invariants 57–70 and 74–81 in [security invariants](security-invariants.md). The authorization
boundary it consumes: [agent-action-authorization.md](agent-action-authorization.md) (unchanged).

> **The agent proposes. The authorization boundary decides. The tool gateway holds the tool and runs it only on Allow.**
> For the one reference tool, `knowledge.lookup`, there is no path inside AgentShield to the tool around the boundary,
> and the agent holds nothing that runs it. Every other tool is still decided, not enforced (section 12).

## 1. Where it sits

```text
UNTRUSTED INPUT
      ↓
INPUT SECURITY             POST /api/v1/firewall/analyze           (Milestones 1–9)
      ↓
AGENT (the caller's runtime) — holds only its AgentShield API key
      ↓  tool call: tool, action, capability, arguments, optional inputEventId / approvalId
      ↓  (no agent, no decision, no grant)
┌─ AGENTSHIELD ─ POST /api/v1/agent/tools/execute ──────────────────────────────────────────┐
│ 0. INPUT CONTEXT         the referenced analysis: this client, this trace, ≤ 10 min     │
│                          (else Block); the strictest input decision wins                │
│ 1. AGENT IDENTITY        the agent whose gateway identity the API key is                 │
│ 2. AUTHORIZATION         M10 boundary: capability, effect-based risk, ordered policy    │
│                          Block → recorded, returned, nothing runs                       │
│                          Review → held + pending approval; runs only when the same call  │
│                          comes back with an approval a person gave, used once           │
│ 3. EXECUTABLE TOOL       an argument policy and an executor exist   (else Block)        │
│ 4. ARGUMENT POLICY       the action's schema → typed arguments      (else Block)        │
│ 5. EXECUTION GRANT       signed, single use, 30 s, bound to this call                   │
│ 6. EXECUTION AUTHORITY   verify signature → consume → expiry → binding → run once       │
└──────────────────────────────────────────────────────────────────────────────────────────┘
      ↓  only for a verified, consumed grant
TOOL                       knowledge.lookup: exact lookup in a fixed in-memory dataset
```

Every stage is recorded (audit log, then activity history) before the next one starts.

## 2. Trust model

| Party | Holds | May | Must not |
|---|---|---|---|
| **Agent** (the caller's runtime) | Its AgentShield API key (`tool:execute`), which identifies exactly one agent | Ask the gateway to run a tool action | Name another agent, assert a decision, a grant, a capability set or a credential (no field exists: 400) |
| **Authorization boundary** (M10, `IAgentActionAuthorizer`) | Trusted configuration: agents, grants, bindings; the reference catalogue | Decide Allow / Review / Block | Execute anything |
| **Tool gateway** (`IToolGateway`, `ToolGateway`) | The order of the stages and the recording | Refuse (Block) what the boundary allowed if no tool runs it or its arguments are invalid | Run a tool itself (it holds none), lift a Review or Block |
| **Execution authority** (`IToolExecutionAuthority`, `ExecutionGrantAuthority`) | The signing key, the grant ledger, the only references to the tools | Issue a grant for what the boundary allows (it asks again); run a tool for a verified, consumed grant, once | Run anything for a grant that is altered, made up, expired, used, or issued for another call |
| **Tool** (`IToolExecutor`, `KnowledgeLookupTool`) | Its dataset | Execute validated arguments | Decide who may call it |

The **execution credential** is the per-execution grant: minted by the authority after an Allow, verified and consumed
before the tool runs, never sent to the agent. The long-lived **execution authority** is the authority's signing key,
generated in memory when the process starts and never configured, logged, returned or exported. The agent's API key only
lets it ask; it never authorises an execution by itself.

## 3. Components

| Layer | Component | Role |
|---|---|---|
| Domain | `ExecutionScope`, `ExecutionGrant` | What a grant authorises; the grant (no decision field) |
| Domain | `ExecutionGrantRejection` | Why a grant was refused (audit vocabulary) |
| Domain | `ToolExecutionOutcome` (+ `ToolExecutionOutcomes`) | How a request ended; exactly one decision per outcome |
| Domain | `ToolArguments`, `KnowledgeLookupArguments`, `ToolArgumentViolation` | Validated arguments; the reference tool's schema; why arguments were rejected |
| Domain | `ToolOutput` | A tool's bounded output (found, text ≤ 2,000 characters) |
| Domain | `ToolGatewayEvent`, `ToolGatewayEventType` | The audit lifecycle (a state machine) |
| Domain | `AgentProfile.GatewayClient` | The client whose key is the agent at the gateway |
| Application | `IToolGateway`, `ToolGateway`, `ExecuteToolRequest` (+ validator), `ToolExecutionResponse` | The use case and its contract |
| Application | `IToolArgumentPolicy`, `IToolExecutor`, `IToolExecutionAuthority`, `IToolGatewayEventSink` | Ports |
| Application | `IAgentDirectory.FindByGatewayClient`, `IApiClientDirectory.ToolExecutionClientIds` | Identity lookups |
| Application | `ToolGatewayActivityRecorder` | One activity record per request (`SecurityActivityKind.ToolExecution`) |
| Security | `ExecutionGrantAuthority` | Issues, verifies, consumes grants; runs tools |
| Security | `KnowledgeLookupArgumentPolicy` | The reference tool's argument policy |
| Security | `ReferenceToolCatalog` | Now also `knowledge.lookup` (`knowledge:read`, ReadOnly, Low) |
| Infrastructure | `KnowledgeLookupTool` | The reference tool (in-memory dataset) |
| Infrastructure | `LoggingToolGatewayEventSink` | Audit log event 1002, `agentshield.tool_gateway_events` metric |
| Infrastructure | `AgentDirectoryOptions` (`GatewayClient`) + validator, `ConfiguredAgentDirectory` | Gateway identities, validated at startup |
| Api | `AgentToolsController`, `Permissions.ToolExecute`, `AuthorizationPolicies.ToolExecute` | The endpoint, its permission and policy |

## 4. Request and response

```json
{ "tool": "knowledge", "action": "lookup", "capability": "knowledge:read",
  "arguments": { "query": "dependency injection" }, "inputDecision": "Allow" }
```

- `tool`, `action`, `capability`: exact names, as for the authorization boundary (422 with a format message that never
  quotes the value). The capability is the one the agent believes authorises the action; the boundary checks it against
  the catalogue (`CapabilityMismatch` otherwise), so it can only block.
- `arguments`: required, a JSON object (missing, `null`, an array or a scalar → 422). What it may contain is the action's
  argument policy's decision (a broken rule → Block, section 6).
- `inputDecision`: optional, `Allow` / `Review` / `Block`; it can only tighten (as in M10; still the caller's report).
- `inputEventId`: optional (Milestone 13), the `securityEventId` of the firewall analysis of the input behind the call. The
  gateway uses the server's record of that analysis, verified (section 17); the caller's `inputDecision` can then only
  tighten it.
- `approvalId`: optional (Milestone 13), the approval a held call received, presented with **the same call** (section 16).
  It authorises nothing by itself.
- **No other field.** `agentId`, `decision`, `riskLevel`, `grants`, `capabilities`, `authorization`,
  `executionAuthorization`, `executionGrant`, `grant`, `executionId`, `signature`, `token`, `credential`, `apiKey`,
  `caller`, `clientId`, … → 400 (strict JSON, ADR 0009). Duplicate members, also inside `arguments` → 400.

Response (200 whatever was decided; `meta.correlationId` traces the request):

```json
{ "data": { "securityEventId": "…", "decision": "Allow", "executed": true, "outcome": "Executed",
            "authorizationReason": "Permitted", "riskLevel": "Low", "executionId": "…",
            "result": { "found": true, "text": "Dependency injection: …" } },
  "meta": { "correlationId": "…", "timestamp": "…" } }
```

For anything that did not run: `executed` is `false`, `result` is `null`, and `executionId` is `null` unless a grant was
issued (only when the authority refused it). `approvalId` is the approval created for a held call, or the one a request
presented; otherwise `null`. The response never echoes the request, never names a rule, the argument rule
that was broken or why a grant was refused, and never carries a grant or a signature. The execution ID authorises nothing.

| Status | Meaning |
|---|---|
| 200 | Decided; `executed` says whether the tool ran |
| 400 | Not valid JSON, or a field beyond the contract |
| 401 / 403 | No valid key / no `tool:execute` |
| 422 | A name is missing or inexact, or `arguments` is not an object |
| 429 | Rate limited (`Standard`, per client) |
| 500 | Not decided, recorded or completed: no decision and no result. If the failure came after the start was recorded, the tool may have run (recorded as `ToolExecutionFailed` or `ToolExecutionCompleted` in the audit log) |

## 5. Agent identity

At the gateway the **API key is the agent**. Configuration:

```json
"AgentAuthorization": { "Agents": {
  "research-agent": { "Capabilities": [ "data:read", "file:read", "browser:navigate", "knowledge:read" ],
                      "Clients": [ "development" ], "GatewayClient": "development" } } }
```

Startup validation (fails in every environment): a `GatewayClient` must hold `tool:execute` and be one of the agent's
`Clients`; a client is the gateway client of at most one agent; **every client holding `tool:execute` is the gateway client
of exactly one agent**. So each gateway credential identifies one agent, and a request through the gateway acts as that
agent and no other: a runtime holding one agent's key cannot act as another (it would need that agent's key). A lookup
that answers for another client is not trusted. `appsettings.json` configures no agent and no client; in Development the
public Development client is research-agent's gateway identity.

## 6. Stages and outcomes

| # | Stage | Fails when | Outcome | Decision |
|---|---|---|---|---|
| 1 | Identity | The caller is no agent's gateway identity (prevented at startup) | — (500) | — |
| 0 | Input context | The referenced analysis is unknown, another client's, another trace's or older than 10 minutes | `InputContextRejected` | Block |
| 2 | Authorization boundary (M10) | Review: High risk or input Review, no approval presented (a pending approval is created when a tool here runs the action) | `HeldForReview` | Review |
| 2 | Approval | Review, and the presented approval is not an approved, unused, unexpired approval of exactly this call | `ApprovalRejected` | Block |
| 2 | Authorization boundary (M10) | Block: unknown agent/tool/action, capability mismatch or not granted, Critical, input Block | `Denied` | Block |
| 3 | Executable tool | No argument policy for the action (e.g. `data.read`) | `ToolUnavailable` | Block |
| 4 | Argument policy | The arguments break the action's schema | `ArgumentsRejected` | Block |
| 5–6 | Grant | The authority refuses the grant (signature, used, expired, binding, no executor) | `ExecutionAuthorizationRejected` | Block |
| 6 | Tool | — | `Executed` | Allow |
| 6 | Tool | The tool throws (500, recorded) | `ExecutionFailed` | Allow (invoked) |

The boundary decides first (an unverifiable input event then blocks whatever it said) and its Block is returned as
decided; its Review is returned as held unless the request presents an approval of exactly this call, which is then used.
Stages 3–6 run only after its Allow, or a Review whose approval this request used, and can only turn it into a Block. `authorizationReason` is always the boundary's reason, so an `ArgumentsRejected` Block reports
the boundary's `Permitted` next to the gateway's outcome.

## 7. Argument policy: `knowledge.lookup`

`KnowledgeLookupArgumentPolicy` (and the `KnowledgeLookupArguments` constructor, which enforces the same schema):

| Rule | Violation |
|---|---|
| A JSON object | `NotAnObject` |
| Exactly one member, named exactly `query` (`Query`, `query2`, `path`, `url`, `decision`, a second `query`, … are rejected) | `UnexpectedArgument` / `MissingArgument` |
| `query` is a string (`null`, numbers, booleans, arrays, objects are not) | `WrongType` |
| Not empty, not only whitespace | `Empty` |
| At most 200 characters | `TooLong` |
| No control characters (line breaks included); well-formed UTF-16 (an escaped lone surrogate is rejected) | `InvalidText` |

The value is kept exactly as sent. The policy never throws for bad input and never puts the value in what it returns; the
violation code goes to the audit log only. The tool matches a query that equals a topic or an alias ignoring case and
surrounding or repeated whitespace (ten topics, deterministic, no partial or fuzzy match), returns dataset text only, and
never logs or returns the query.

## 8. Execution grants

| Property | How |
|---|---|
| Bound | Scope = security event, correlation ID, agent, tool, action, capability; compared exactly with the call the gateway builds from its own request |
| Short-lived | Expires 30 s after issue (`ExecutionGrantAuthority.Lifetime`); at or after expiry it runs nothing |
| Single use | Held in a ledger until presented; presenting removes it atomically; a second presentation → `AlreadyUsed` |
| Unforgeable | HMAC-SHA256 over a length-prefixed encoding of every field and a context label, under a per-process random 256-bit key; verified in constant time before the ledger is touched |
| Allow only | `Issue` asks the boundary again and returns nothing unless it allows exactly this request; no decision field |
| Not the agent's | Never in a response; no request field can carry one |

Checks when a grant is presented, in order: signature (`InvalidSignature`, ledger untouched) → consume → expiry
(`Expired`) → not already used (`AlreadyUsed`) → agent, tool, action, capability (`WrongAgent`, `WrongTool`,
`WrongAction`, `WrongCapability`) → request (`WrongRequest`) → an executor for the call (`NoExecutor`). A grant with a
valid signature is consumed even when a later check refuses it. The ledger holds at most 4,096 outstanding grants; expired
ones are purged on issue; beyond the bound the request fails (500) rather than evicting a live grant. In this prototype the
grant never leaves the process, so issue and presentation are milliseconds apart; the protections matter for future
asynchronous or out-of-process execution and as defence in depth against gateway bugs.

## 9. Complete mediation

There is no application path to the reference tool except through the gateway:

- `IToolExecutor` is held only by `ExecutionGrantAuthority`; `IToolExecutionAuthority` only by `ToolGateway`;
  `IToolGateway` only by `AgentToolsController` — checked over the constructors and fields of every type in every
  AgentShield assembly (`ToolGatewayPipelineTests.CompleteMediation_OnlyTheExecutionAuthorityHoldsATool_AndOnlyTheGatewayHoldsTheAuthority`).
- `KnowledgeLookupTool` is internal and sealed, registered only as `IToolExecutor`, not resolvable as itself.
- One endpoint requires `ToolExecute`, and nothing else lives under the tools route (endpoint inventory test).
- The authority runs a tool only after verifying and consuming a grant, and issues a grant only for what the boundary
  allows. Every HTTP test runs with a probe around every executor, the real tool included, so "the tool did not run" is
  observed, not inferred.

## 10. Recording

| Stage | Audit log (event 1002, `ToolGatewayStage`) | Level | Activity history |
|---|---|---|---|
| `ToolAuthorizationRequested` | agent, input decision, referenced input event ID; tool fields `(pending)` | Information | — |
| `ToolAuthorizationAllowed` | + recognised names, decision, reason, risk, execution ID, approval ID (if one was used) | Information | — |
| `ToolAuthorizationBlocked` / `…Reviewed` | + outcome, argument violation, input context rejection, approval ID, approval rejection | Warning | — |
| `ToolExecutionStarted` | + execution ID | Information | — |
| `ToolExecutionCompleted` | outcome `Executed` | Information | one record |
| `ToolExecutionRejected` | outcome (+ grant rejection) | Warning | one record |
| `ToolExecutionFailed` | outcome `ExecutionFailed` | Error | one record |

All entries of a request share its security event ID and carry the client ID (log context). Names AgentShield does not
recognise are `(unknown)`. Never the arguments, the tool's result or a signature. Every stage is counted in
`agentshield.tool_gateway_events` (tag `stage`), whether or not it is written; outside Development the API refuses to start
if the log level hides this sink's category. The activity record (`SecurityActivityKind.ToolExecution`) has the decision,
risk level (no score), the recognised agent action with the boundary's reason, and `toolExecution` = outcome, executed,
execution ID; it never holds the arguments, the result, the argument violation or the grant rejection (nor, since
Milestone 13, the input context or approval rejection). A person's decision on an approval is audit event 1003
(`ToolApprovalEvent`, section 16), not an activity record.

Since Milestone 13 every recording path shares one helper (`EventSinks.PublishToEveryAsync`): every sink gets the entry
whatever another sink does, a failure included **and a cancellation included**; then a failure is raised (one as itself,
several as an aggregate), and otherwise the cancellation. Before, the first sink to throw `OperationCanceledException`
stopped the loop, so a cancelled request could leave one sink with an entry the others skipped. After the grant is
consumed, the gateway records `GrantRefused`, `Completed` and (D-21) `Failed` with a token of its own.

## 11. High-impact action model

The same gateway with harmless test executors for more catalogued actions (`ToolGatewayRiskModelTests`): the policy's
decision is consumed unchanged; executors do not lower it.

| Risk | Example | Decision | Tool runs |
|---|---|---|---|
| Low | `knowledge.lookup` | Allow | Yes |
| Medium | `data.write` | Allow (Review with an input under review) | Yes (No) |
| High | `email.send`, `browser.navigate` | Review | No |
| Critical | `payment.execute` (capability held) | Block | No |

## 12. Threat model

| Threat | Example | Control | Residual |
|---|---|---|---|
| Executing around AgentShield (M10 bypass 1) | The runtime calls the tool directly | The tool lives behind the gateway; the agent holds no credential for it; only the authority holds the tool | Only for tools behind the gateway (one); other tools are still the caller's |
| Agent impersonation (ASI03, M10 bypass 2) | Runtime B sends agent A's ID | No agent field (400); the agent is the key's | A stolen key is that agent |
| Self-asserted authority | Body adds `decision`, `executionGrant`, `approved`, `capabilities` | Strict JSON → 400 | — |
| Forged or altered grant | A grant made up in code, or with an extended expiry | Signature over every field, per-process key | Code inside the process is trusted (as everywhere) |
| Replay (M10 bypass 5) | Present a used grant again, concurrently or later | Single-use ledger, atomic consumption, 30 s expiry | Ledger is per process |
| Grant reuse for another call | A lookup grant used for `data.write` or another agent | Exact binding to the call the gateway builds | — |
| Argument smuggling (M10 bypass 4) | `{"query":"x","path":"/etc/passwd"}`, `{"query":{"$ne":""}}`, 100,000 characters, control characters | Per-tool argument policy → Block; the tool only receives typed, validated arguments | Only the reference tool has a policy; semantic abuse of a valid query is not checked |
| Review or Block executed anyway | A High action with an executor present | The boundary's decision is consumed; only Allow reaches a grant | — |
| Unknown tool or action | `shell.exec`, `knowledge.delete` | Boundary → Block (Critical) | — |
| Allowed action without a tool | `data.read` | `ToolUnavailable` → Block | — |
| Recording bypass | The activity store fails | Every sink tried at every stage; 500 before the next stage | After `Started`, the tool may run without a terminal entry if the process dies |
| Result leakage into history | A sensitive result stored as activity | Results and arguments are never recorded | The response carries the result to the caller |
| Input decision replaced (M10 bypass 3) | The firewall blocked the input; the runtime claims `Allow` | A referenced analysis is the server's record, verified (client, trace, age); the claim only tightens (section 17) | A runtime that references **no** analysis is decided on the action alone |
| Review executed without a person | Re-submit a held call, or claim `approved` | No approval field but an ID the server created; `TryUse` requires Approved by a person; the authority re-checks the use | — |
| Approval replay | Present a used approval again, concurrently or later | Atomic use by one request's security event; Used is final | Per process |
| Approval transfer | Use agent A's approval for agent B, another tool, action, capability or arguments | Exact binding (agent from the key, client, tool, action, capability, SHA-256 of the arguments as sent, input event) | — |
| Self-approval | The agent's own key approves its call | `agent:approve` is its own permission; outside Development no client holds it with `tool:execute` or `agent:authorize` (startup fails) | Development's public key holds both, for the demo |
| Approval used before it is audited | Present the call while the decision is being recorded | Two-phase decision: reserved, recorded, then completed; meanwhile the approval is Pending (unusable); a failed recording withdraws it | — |
| Stale approval | Approve a call hours later, or run it long after approval | One lifetime (default 10 minutes) from the request, checked on every decision and use | — |

## 13. Security test matrix

| Scenario | Expected | Evidence |
|---|---|---|
| Allow | Tool runs exactly once with the validated arguments | `ToolGatewayEndpointTests.Execute_AnAllowedLookup_RunsTheToolExactlyOnce_AndReturnsItsResult`; `ToolGatewayTests.ExecuteAsync_Allow_RecordsRequestedAllowedStartedCompleted_ThenRunsOnce_AndReturnsTheResult` |
| Block / Review (every boundary reason) | Tool not called | `ToolGatewayEndpointTests.Execute_AnythingTheBoundaryDoesNotAllow_IsReturnedAsDecided_AndTheToolNeverRuns` (15 rows); `ToolGatewayTests.ExecuteAsync_EveryNonAllowReason_IsReturnedAsTheBoundaryDecidedIt_WithoutExecution` |
| Unknown tool / unknown action | Not called | Same theory (`shell.exec`, `knowledge.delete`, `knowledge.search`) |
| Missing capability / wrong capability | Not called | Same theory (reader agent; `data:read`, `knowledge:write` claims) |
| Invalid arguments (16 shapes) | Not called; Block `ArgumentsRejected` | `Execute_ArgumentsOutsideTheSchema_AreBlocked_AndTheToolNeverRuns`; `KnowledgeLookupArgumentPolicyTests` |
| Arguments not an object / missing / null | 422, not called | `Execute_ArgumentsThatAreNotAnObject_Return422_AndNothingRuns` |
| Malformed or ambiguous JSON | 400, not called | `Execute_AmbiguousOrMalformedBody_Returns400_AndNothingRuns` |
| Authority-asserting fields | 400, not called | `Execute_AnyFieldBeyondTheContract_Returns400_AndNothingRuns` (26 fields) |
| Expired grant | Not called | `ExecutionGrantAuthorityTests.ExecuteAsync_AnExpiredGrant_RunsNothing_AndIsGoneFromTheLedger` |
| Already-used grant (sequential, concurrent ×64) | Called once | `ExecuteAsync_AGrantPresentedTwice_RunsOnce`, `ExecuteAsync_ConcurrentPresentations_ExactlyOneRuns` |
| Wrong agent / tool / action / capability / request | Not called; grant burnt | `ExecuteAsync_AGrantForAnotherCall_RunsNothing_AndIsBurnt`, `ExecuteAsync_AGrantForKnowledgeLookup_CannotRunAnotherTool` |
| Forged or altered grant (13 alterations), foreign key | Not called; real grant still valid | `ExecuteAsync_AnAlteredGrant_IsRefused_WithoutTouchingTheRealOne`, `ExecuteAsync_AGrantFromAnotherAuthority_IsRefused` |
| Block / Review never granted | No grant for any non-Allow over the catalogue | `Issue_NothingTheBoundaryDoesNotAllow_EverGetsAGrant`, `Issue_EveryNonAllowOverTheWholeCatalogue_GetsNoGrant`, `Issue_TheAuthorityAsksTheBoundaryItself_NotTheCallersVerdict` |
| Identity | Same body, different key → different agent; no agent field | `Execute_TheAgentIsTheCredentials_TheSameBodyDecidesPerKey`, `Execute_ACredentialCannotNameAnotherAgent`; `ToolGatewayPipelineTests.ADedicatedGatewayCredential_ActsAsItsAgentOnly` |
| Complete mediation | Only the authority holds a tool | `CompleteMediation_*`; `EndpointInventory_TheGatewayIsTheOnlyEndpointThatCanExecute_AndRequiresExactlyToolExecute` |
| Recording failure at each stage | 500; no grant before Requested, no run before Started | `Execute_RecordingFailsAtAStage_…` (4 stages); `ToolGatewayTests.ExecuteAsync_ASinkFailsAtAStage_…` |
| Risk model | Low/Medium run; High Review; Critical Block | `ToolGatewayRiskModelTests` (20 combinations) |
| Privacy | No arguments, results or made-up names in responses, activity or logs | `Activity_NeverHoldsTheArgumentsTheResultOrMadeUpNames`, `AuditLog_RecordsTheArgumentRuleThatWasBroken_ButNeverTheArgumentsOrTheResult`, `Execute_Response_HasExactlyTheDocumentedFields_AndNeverEchoesTheRequest` |
| Access | 401 / 403; the gateway key can do nothing else | `Execute_Anonymous_Returns401_AndNothingRuns`, `Execute_ClientWithoutToolExecute_Returns403_AndNothingRuns`, `GatewayCredential_CannotAuthorizeAnalyzeOrReadActivity`; `RateLimitingTests.ToolGateway_…` |
| Review without approval (M13) | Held, pending approval of exactly this call, not called | `ToolGatewayApprovalTests.Review_WithoutAnApproval_IsHeld_RunsNothing_AndCreatesAPendingApprovalOfExactlyThisCall`; `ToolApprovalEndpointTests.AHighRiskCall_IsHeld_WithAPendingApproval_AndNothingRuns` |
| Approved, then the same call | Called once; replay not called | `Approved_ThenTheSameCall_RunsExactlyOnce_AndAReplayRunsNothing`; `ApprovedReview_PresentedTwice_RunsOnce`; `InMemoryToolApprovalStoreTests.TryUse_ConcurrentPresentations_ExactlyOneWins` (64) |
| Denied / expired / pending / unknown approval | Not called | `Denied_ThenTheSameCall_RunsNothing_AndTheDecisionIsFinal`, `Expired_CannotBeApproved_AndTheCallRunsNothing`, `AHeldCall_WithoutAValidApproval_RunsNothing`, `UnknownOrMalformedApproval_IsRefused_WithoutEchoingIt` |
| Approval for another call, tool or agent | Not called | `AnApproval_NeverAuthorisesAnotherCall_AnotherToolOrAnotherAgent`; `ToolGatewayApprovalTests.AnApproval_ForOneCall_DoesNotAuthoriseOtherArguments_OrAnotherAgent`; `ToolApprovalTests.Use_AnApprovalForOneCall_NeverAuthorisesAnother` |
| Approval asserted by the body | Ignored or 400 | `Deciding_TakesNothingFromTheClient_ABodyAssertingAuthorityChangesNothing`; `AttackLabScenarioTests.ScenarioMetadata_InAToolCall_…` (`approved`) |
| Block with an approval | Not called; approval unused | `ToolGatewayApprovalTests.ABlock_IsNeverLiftedByAnApproval_AndLeavesItUnused` |
| Approval used while being recorded | Refused | `DecideToolApprovalUseCaseTests.ExecuteAsync_WhileTheApprovalIsBeingRecorded_ItCannotBeUsedOrDecidedAgain_ItTakesEffectOnlyAfterwards` |
| Approver permission and separation of duties | 403 for every other client; startup fails for a combined client outside Development | `OnlyAnApprover_MayListApproveOrDeny`, `EndpointInventory_TheApprovalEndpoints_RequireExactlyTheApprovalPolicy`; `ToolApprovalPipelineTests.AnApproverThatIsAlsoAnAgentCredential_FailsAtStartup_OutsideDevelopment` |
| Input event: Block / Review / Allow / unverifiable | Block stays Block; Review needs approval; Allow still authorised; unverifiable → Block | `ToolApprovalEndpointTests.ABlockedInput_CannotBecomeAnAllow_WhateverTheCallerClaims`, `AnInputHeldForReview_RunsOnlyAfterAPersonApproves`, `AnAllowedInput_StillNeedsTheActionsOwnAuthorization_AndThenRuns`, `AnInputEventThatCannotBeVerified_BlocksTheCall`; `ToolGatewayApprovalTests.AnInputEventThatCannotBeVerified_BlocksTheCall_WhateverTheBoundarySays` (4 rejections) |
| Arguments under one grant (F7) | The tool receives exactly the validated arguments of the same request | `ToolGatewayApprovalTests.TheToolGetsExactlyTheArgumentsValidatedInTheSameRequest_UnderThatRequestsOneGrant` |
| Recording under cancellation | Every sink records; post-execution entries still written | `EventSinksTests` (7), `ToolGatewayApprovalTests.ACancelledSink_DoesNotSkipTheOtherSinks`, `ARequestCancelledAfterTheToolRan_StillRecordsTheCompletion` |

## 14. The M10 bypasses after M11

| M10 bypass | Status |
|---|---|
| 1. The caller can execute the tool anyway | **Closed for tools behind the gateway** (`knowledge.lookup`). Open for every other tool |
| 2. The runtime chooses the agent among its bound agents | **Closed at the gateway** (the key is the agent). Unchanged at `/agent/actions/authorize` |
| 3. The reported input decision is not tied to the input's security event | **Closed when the call references its analysis** (Milestone 13, `inputEventId`). Open when it references none: the call is then decided on the action and the caller's report, which only tightens |
| 4. Tool arguments are not checked | **Closed for the reference tool** (argument policy). Other tools have none |
| 5. Allow is not a signed, single-use authorization | **Closed inside the gateway** (execution grants). The M10 endpoint's Allow is still a plain decision |

## 15. Not built

Out-of-process tool servers (the grant would cross a process boundary: shared or asymmetric keys, replay storage),
MCP and real tools, argument policies for tools other than the reference tool, tool-output screening and indirect prompt
injection, per-agent rate limits, distributed or persistent grant state, and a hard timeout around tool execution (the
reference tool is in memory). Since Milestone 13 Review can be released by a person, and a call can be tied to its input's
analysis; still not built: a **mandatory** input reference, approval routing, approver roles or quorum, notifications,
editing a held call, durable or multi-instance approvals, and a high-risk tool with a real executor (the only executable
tool is the read-only lookup, so the approval that can actually run is one held because of its input).

## 16. Human approval (Milestone 13)

```text
agent ──call──▶ gateway: boundary says Review ──▶ HeldForReview + approvalId     (approval: Pending)
person ──POST /api/v1/agent/approvals/{id}/approve (agent:approve, no body)──▶      (approval: Approved, recorded first)
agent ──the same call + approvalId──▶ gateway: boundary again (Review) → TryUse → arguments → grant → tool once
                                                                                    (approval: Used, by this request)
```

| Rule | How |
|---|---|
| Review never becomes Allow by itself | Only a request presenting an approval runs a Review, and only after `TryUse` succeeds |
| An approval is created by the server | Only the gateway creates one, for a Review it holds when a tool here runs the action; its ID is a random v4 GUID |
| Bound to exactly one call | Agent (from the key), client, tool, action, catalogue capability, SHA-256 of the arguments as sent, the referenced input event; any difference → `ApprovalRejected` |
| Decided once, by a person | `agent:approve`; the decider is the authenticated client; Pending only; reserved, recorded (event 1003), then completed; a failed recording withdraws it (Denied) |
| Used once | `TryUse` is atomic under the store's lock: Approved, unexpired, binding equal → Used by this request's security event |
| The authority checks it too | `ExecutionGrantAuthority.Issue` grants a Review only if the store says the approval is Used by this very request and bound to this agent, client, tool, action and capability |
| Expiry | `requestedAt + ToolApprovals:LifetimeSeconds` (default 600, 1–86,400) for both deciding and using |
| A Block is never lifted | The boundary decides afresh on every request; a Block is `Denied` and leaves a presented approval unused; an Allow runs without using it |
| Separation of duties | Outside Development, `agent:approve` cannot be combined with `tool:execute` or `agent:authorize` (startup fails) |
| Metadata only | List and decision responses: IDs, status, agent, tool, action, capability, risk, reason, input decision, times. Never the arguments, their digest or a client |

Endpoints (all `agent:approve`, `Standard` rate limit): `GET /api/v1/agent/approvals` (newest 50),
`POST /api/v1/agent/approvals/{approvalId}/approve`, `POST /api/v1/agent/approvals/{approvalId}/deny`. 400 for an ID
that is not a GUID, 404 `Approval.NotFound`, 409 `Approval.AlreadyDecided` (also while another decision is being
recorded), 409 `Approval.Expired`; no message quotes the ID. Store: in memory, per process, 1,000 approvals, open ones never evicted (a new
hold fails closed with 500 when 1,000 are open).

## 17. Input event binding (Milestone 13)

Every firewall analysis is recorded as an **input security context** (event ID, correlation ID, analysing client,
decision, time; no content) by `InputSecurityContextRecorder`, one of the firewall's security-event sinks, into an
in-memory store (10,000 records, 10 minutes). A gateway request that carries `inputEventId` is checked:

| Check | Fails as (audit only) |
|---|---|
| The server holds the analysis | `NotFound` |
| The same client submitted the input | `OtherClient` |
| The same trace (the request's correlation ID is the analysis's) | `OtherTrace` |
| It is at most 10 minutes old | `Expired` |

Any failure is `InputContextRejected` (Block), whatever the boundary would have said. Otherwise the input decision the
boundary weighs is the **strictest** of: the verified analysis, the input decision recorded in a presented approval, and the
caller's `inputDecision`. So an input Block stays Block, an input Review needs a person's approval, and an input Allow
still needs the action's own authorization. An agent re-submitting an approved call does not need to reference the input
again: the approval carries it (re-sending the reference from another trace is refused like any other).

## 18. Trust boundary chain

```text
INPUT (untrusted)
  → FIREWALL decides (deterministic rules, optional AI as one input)      server record: security event + input context
  → AGENT proposes a call (untrusted: key = identity, body = request only) references the analysis by ID, or not
  → GATEWAY verifies the input reference (client, trace, age)              strictest input decision wins
  → AUTHORIZATION BOUNDARY decides Allow / Review / Block                  trusted configuration and catalogue only
  → PERSON approves or denies a Review (agent:approve, a separate client) recorded before it takes effect
  → GATEWAY uses the approval once, for exactly this call                  atomic, bound, expiring
  → ARGUMENT POLICY builds typed arguments                                 or Block
  → EXECUTION AUTHORITY re-checks the boundary (and the approval's use), issues, verifies and consumes one grant
  → TOOL runs once                                                         every stage audited before the next
```

What each party cannot do: the agent cannot name an agent, a decision, a risk, a grant or an approval status (no field);
it cannot replace the firewall's decision of an input it references (strictest wins), nor run a Review without a
person, nor reuse or transfer an approval. A person cannot lift a Block (the boundary decides afresh) or approve a call
the gateway did not hold. The gateway holds no tool; the authority runs nothing without a grant it issued for this
request.
