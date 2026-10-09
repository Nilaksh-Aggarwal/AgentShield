# Agent action authorization

The authorization boundary for agent actions (Milestone 10): before an agent calls a tool, AgentShield decides whether it
may — **Allow, Review or Block**. It decides; it never executes. Decision record:
[ADR 0020](../decisions/0020-agent-action-authorization-boundary.md). Guarantees and their evidence: invariants 44–52 in
[security invariants](security-invariants.md).

> **AI proposes. The authorization boundary decides. A tool executor may act only on an Allow.**
> This boundary executes nothing. Since Milestone 11 the [tool gateway](tool-gateway.md) executes its one reference tool,
> `knowledge.lookup`, only on this boundary's Allow; for every other tool the application that runs the agent must call
> the boundary and enforce its answer (section 9).

## 1. Where it sits

```text
USER / UNTRUSTED CONTENT
        ↓
INPUT SECURITY            POST /api/v1/firewall/analyze      (built: Milestones 1–9)
        ↓  Allow / Review / Block
AGENT (the caller's runtime; not AgentShield)
        ↓  proposes a tool action
ACTION REQUEST            POST /api/v1/agent/actions/authorize (built: Milestone 10)
        ↓
CALLER AND AGENT          configured agent, bound to the authenticated API client
        ↓
CAPABILITY CHECK          catalogued tool action; exactly its required capability; held by the agent
        ↓
RISK CLASSIFICATION       from the action's declared effects (deterministic, no AI)
        ↓
POLICY                    ordered rules; the input decision can only tighten
        ↓
ALLOW / REVIEW / BLOCK    returned, recorded in the audit log and the activity history
        ↓
TOOL EXECUTION            the tool gateway for knowledge.lookup (Milestone 11, tool-gateway.md);
                          the caller's runtime for every other tool
```

Two different authorizations appear in this request and must not be confused: the API **caller** is authenticated
(`X-API-Key`) and authorised (`agent:authorize`) at the HTTP boundary (ADR 0014); the **agent action** is authorised by
this boundary, inside the use case.

## 2. Components

| Layer | Component | Role |
|---|---|---|
| Domain | `AgentId`, `ToolId`, `ActionName`, `Capability` | Exact, validated names (`AgentIdentifiers`) |
| Domain | `ToolActionDefinition` | A catalogued action: required capability and declared `ActionEffects` |
| Domain | `AgentProfile` | A configured agent: granted capabilities and bound callers, immutable |
| Domain | `AgentActionRequest` | The proposal: caller (from authentication), agent, tool, action, claimed capability, optional input decision |
| Domain | `AgentActionReason`, `AgentActionAuthorization` | The verdict: reason → decision (one each), risk, recognised names |
| Domain | `AgentActionEvent` | The audit record of one decision |
| Application | `IAgentActionAuthorizer` | The boundary (port) |
| Application | `IToolCatalog`, `IAgentDirectory` | Trusted data (ports) |
| Application | `IAgentActionEventSink` | Recording (port): audit log and activity history |
| Application | `AuthorizeAgentActionUseCase` | Builds the proposal, asks the boundary, records, returns the verdict unchanged |
| Security | `AgentActionAuthorizer` | Establishes facts from trusted data, classifies risk, applies the policy |
| Security | `ActionRiskClassifier`, `AgentActionPolicy` | Deterministic risk and policy |
| Security | `ReferenceToolCatalog` | The fixed reference catalogue (section 5) |
| Infrastructure | `ConfiguredAgentDirectory` + `AgentDirectoryOptions` | Agents from configuration, validated at startup |
| Infrastructure | `LoggingAgentActionEventSink` | The audit log entry (event 1001) and a decision metric |
| Application | `AgentActionActivityRecorder` | The activity record (`SecurityActivityKind.AgentActionAuthorization`) |
| Api | `AgentActionsController` | `POST /api/v1/agent/actions/authorize`, policy `AgentAuthorize`, `Standard` rate limit |

## 3. Request

```json
{ "agentId": "support-agent", "tool": "email", "action": "send", "capability": "email:send", "inputDecision": "Allow" }
```

- `agentId`, `tool`, `action`: 1–64 characters of `a-z 0-9 . _ -`, starting with a letter or digit. `capability`:
  `resource:operation`, each part `a-z 0-9 _ -`, at most 64 characters. Missing or malformed → **422** (the message
  describes the format, never the value). Nothing is normalised: `Email`, ` email` or a Cyrillic look-alike is invalid,
  never another spelling of `email`.
- `inputDecision` (optional): `Allow`, `Review` or `Block`, the firewall's decision on the input behind the action, as
  the caller reports it (section 7). Any other value → **400**.
- **There is no other field.** Strict JSON (ADR 0009) turns `decision`, `riskLevel`, `approved`, `capabilities`,
  `arguments`, `reasoning`, `caller` or any other property into a **400**. The agent cannot assert its own authority,
  grant itself a capability, or attach reasoning the policy would have to weigh.
- **No tool arguments.** A policy that does not read arguments cannot vouch for them; accepting them would suggest a
  check that does not exist. Argument-level policy is future work (section 11).

Response (200 whatever the decision; the envelope's `meta.correlationId` traces the request):

```json
{ "data": { "securityEventId": "…", "decision": "Review", "riskLevel": "High", "reason": "HumanApprovalRequired" },
  "meta": { "correlationId": "…", "timestamp": "…" } }
```

The response never echoes the request and never names a rule, a catalogue entry, the agent's grants or the caller.
**Only `Allow` permits executing the action.** Review means a person must approve it first; Block, any 4xx and any 5xx
mean it must not run.

## 4. Capabilities and caller binding

- A capability is an exact name, not a pattern: no wildcards, no hierarchy. `email:send` is held only by an agent
  granted exactly `email:send`.
- A tool is not a unit of permission. Each action has its own required capability and its own risk (`email`: read Low,
  draft Medium, send High). One capability may authorise several actions of the same risk (`data:read`: describe, read).
- The capability that is checked is **the one the catalogue requires**, and it counts only if the **configured profile**
  holds it. The claimed capability must merely be equal to it; a different claim is `CapabilityMismatch` (Block), even
  when the agent holds the claimed capability.
- Agents and their grants come from configuration (`AgentAuthorization:Agents:{agentId}`), read once at startup into an
  immutable directory. There is no runtime operation that adds an agent, a capability or a binding.
- **Caller binding.** Each agent lists the API clients (`Clients`) allowed to request decisions for it — typically the
  runtime that executes its tool calls. The caller comes from authentication, never from the body. A client that names an
  agent it is not bound to gets `CallerNotBoundToAgent` (Block), so holding `agent:authorize` does not let one runtime
  borrow another agent's grants.
- Startup validation (fails outside and inside Development): agent IDs and capabilities must be valid names; every
  capability must be one the catalogue requires; every agent must be bound to at least one client, and each bound client
  must be configured with `agent:authorize`. Messages name the agent, never the rejected value.

```json
"AgentAuthorization": {
  "Agents": {
    "support-agent": { "Capabilities": [ "data:read", "email:read", "email:draft", "email:send" ], "Clients": [ "development" ] }
  }
}
```

`appsettings.json` configures **no agent**: a deployment that does not configure any blocks every agent action
(`UnknownAgent`). The four demo agents (support, research, operations, finance) are in `appsettings.Development.json`,
bound to the public Development client.

## 5. Reference tool catalogue

Defined in code (`ReferenceToolCatalog`) because each entry is security policy, pinned by `ReferenceToolCatalogTests`.
Only `knowledge.lookup` is implemented, behind the [tool gateway](tool-gateway.md) (Milestone 11); none of the others
is implemented or executed by AgentShield.

| Tool | Action | Required capability | Declared effects | Risk |
|---|---|---|---|---|
| data | describe | `data:read` | MetadataLookup | Low |
| data | read | `data:read` | ReadOnly | Low |
| data | write | `data:write` | ModifiesData | Medium |
| data | delete | `data:delete` | Destructive | Critical |
| email | read | `email:read` | ReadOnly | Low |
| email | draft | `email:draft` | DraftForApproval | Medium |
| email | send | `email:send` | ExternalCommunication | High |
| file | read | `file:read` | ReadOnly | Low |
| file | write | `file:write` | ModifiesData | Medium |
| browser | navigate | `browser:navigate` | ExternalCommunication (a page load reaches a third party and can carry data in its URL) | High |
| browser | submit | `browser:submit` | ExternalCommunication, ModifiesData | High |
| customer | update | `customer:write` | ModifiesSensitiveData | High |
| payment | execute | `payment:execute` | Financial | Critical |
| secrets | read | `secrets:read` | CredentialAccess | Critical |
| identity | grant | `identity:grant` | PrivilegeChange | Critical |
| knowledge | lookup | `knowledge:read` | ReadOnly (a lookup in a fixed in-memory dataset; Milestone 11) | Low |

## 6. Risk classification

`ActionRiskClassifier`: the action is as risky as its most dangerous declared effect. Deterministic; no AI, no score, no
name matching. Adding an effect never lowers the level (tested over all 2,047 combinations).

| Level | Effects |
|---|---|
| Low | ReadOnly, MetadataLookup |
| Medium | ModifiesData (non-sensitive), DraftForApproval |
| High | ExternalCommunication, ModifiesSensitiveData, PrivilegedOperation |
| Critical | Financial, CredentialAccess, Destructive, PrivilegeChange |

An action with no declared effect is invalid (`ToolActionDefinition` rejects it), and an unknown effect bit throws: "no
effect" is an unclassified action, not a safe one. An action AgentShield cannot classify (unknown tool or action) is
reported as **Critical**. The reported risk is the action's, not the request's: a Low read the agent may not perform is
Low risk and blocked.

## 7. Policy

`AgentActionPolicy`, evaluated top-down; the first rule that applies gives the reason, and each reason has exactly one
decision (`AgentActionReasons.DecisionFor`, so the two cannot disagree).

| # | Condition | Reason | Decision |
|---|---|---|---|
| 1 | Agent not configured | `UnknownAgent` | Block |
| 2 | Caller not bound to the agent | `CallerNotBoundToAgent` | Block |
| 3 | Tool not catalogued | `UnknownTool` | Block |
| 4 | Action not catalogued | `UnknownAction` | Block |
| 5 | Claimed capability ≠ required capability | `CapabilityMismatch` | Block |
| 6 | Agent does not hold the required capability | `CapabilityNotGranted` | Block |
| 7 | Risk Critical (`DenyAt`) | `CriticalActionDenied` | Block |
| 8 | Input decision Block | `InputBlocked` | Block |
| 9 | Risk High (`ReviewAt`) | `HumanApprovalRequired` | Review |
| 10 | Input decision Review | `InputHeldForReview` | Review |
| 11 | Otherwise (Low or Medium, granted) | `Permitted` | Allow |

- Every Block rule precedes every Review rule, which precede Allow. So the decision is the strictest that any fact calls
  for: a higher risk or a stricter input decision never lowers it, losing any fact never makes it more permissive, and
  the result is never below the reported input decision (tested over the whole input space: 1,024 combinations).
- **Critical actions are denied to every agent**, even one that holds the capability: there is no approval workflow strong
  enough (dual control, step-up) to release them one at a time (the Milestone 13 approval releases a Review only; a
  Critical Block is never approvable). The capability can still be granted, so a later workflow
  can lift the ceiling without regranting, and so the reason distinguishes "not granted" from "critical".
- **The input decision is evidence, not authority.** The caller reports the firewall's decision on the input behind the
  action; it can only raise the decision. Reporting `Allow` changes nothing; omitting it means "no evidence". AgentShield
  does not verify it against its own records (section 9).
- Undefined risk or input-decision values throw (fail closed, 500) rather than being read as Low or absent.

## 8. Recording

Every decision is one `AgentActionEvent`, built after the boundary decided and given to every `IAgentActionEventSink`
(the same contract as the firewall's security events): every sink is tried, then a failure fails the request closed —
**500, no decision** — while the other sinks still record.

- **Audit log** (`LoggingAgentActionEventSink`, event ID 1001, Information for Allow, Warning otherwise): event and
  correlation IDs, decision, reason, risk, recognised agent, tool, action and claimed capability, the reported input
  decision, duration, and the client ID (log context). The `agentshield.agent_action_events` metric counts every decision
  by decision, whether or not the entry is written. Outside Development the API refuses to start if the log level hides
  this sink's category.
- **Activity history** (`SecurityActivityKind.AgentActionAuthorization`): event and correlation IDs, time, decision, risk
  level (score `null`), and `agentAction` = agent, tool, action, claimed capability and reason. Findings are empty and
  `aiAnalysis` is `null`. Not recorded: the input decision, the duration, the caller.
- **Closed vocabulary.** Only names AgentShield's own configuration recognises (`RecognisedAgentAction`) are recorded. A
  name the caller made up — an unknown agent, tool, action or capability — is recorded as `null` (activity) or
  `(unknown)` (log), never verbatim, so an agent cannot use the request to write text of its choosing into the history.
  There are no tool arguments to record.

There is deliberately no activity kind per decision ("AgentActionAllowed", "…Blocked"): the record's decision says that,
and a kind that restated it could disagree with it. "Tool authorization failed" is a Block with a denial reason; a
failure to decide is a 500 with no decision (and no record of a decision).

## 9. Is the boundary enforceable by construction?

**Inside AgentShield, yes, for what it decides:**

- Nothing the agent sends can grant a capability or lower a decision. Agent profiles, bindings and tool definitions are
  trusted, immutable data; the request has no field for authority (400 otherwise); the claimed capability can only match
  or block; the input decision can only tighten. Proven per agent, action, claim and input decision against the real
  catalogue (`AgentActionAuthorizerTests.Authorize_NoClaimedCapabilityOrInputDecision_CanLowerTheHonestDecision`).
- Unknown means Block, in the policy and again in the domain: an `AgentActionAuthorization` that allows or reviews a
  request with an unrecognised name cannot be constructed.
- A lenient or wrong catalogue or directory cannot widen what matches: an answer for another name than the one asked is
  ignored.
- AgentShield executes nothing, so no code path inside it runs a tool around the boundary.

**Outside AgentShield, no — there are paths around it:**

1. **Enforcement is the caller's** — except for the tools behind the tool gateway (Milestone 11: `knowledge.lookup`).
   For every other tool AgentShield is a decision point, not an enforcement point: a runtime that never asks, ignores the
   answer, treats a 5xx or a timeout as "go", or executes on Review without a person, bypasses it entirely.
2. **Agent identity is asserted by the runtime.** The caller binding limits a client to its own agents, but within them
   the runtime chooses which agent ID to send. A compromised runtime can act as any agent bound to it. (At the tool
   gateway the API key is the agent: closed there.) Reviewed again in Milestone 13 (Part 15): not a bypass of anything
   that executes. This endpoint only decides; the only tool AgentShield runs is reached through the gateway, where the
   agent comes from the key (`IAgentDirectory.FindByGatewayClient`, exact match, startup-validated one-to-one), and an
   approval is bound to that agent. Left open by design for this decide-only endpoint, and documented.
3. **The input decision is self-reported here.** A runtime can omit it or report `Allow` for an input the firewall blocked.
   It can only make the result stricter, never looser, but this endpoint does not verify it against the security event.
   (At the tool gateway, since Milestone 13, a call can reference the analysis by `inputEventId` and is then decided on
   the server's record; the reference is optional.)
4. **No arguments are checked here.** An allowed `email.send` is allowed for any recipient and content; `email:send` is
   High, so it is held for review, but a Medium action such as `data.write` is allowed for any data. (The tool gateway
   checks the reference tool's arguments.)
5. **No replay or binding of the decision.** This endpoint's Allow is not a signed, single-use, time-bound token;
   nothing ties it to the execution that follows. (Inside the tool gateway an Allow becomes a signed, single-use,
   30-second execution grant bound to the call.)

## 10. Threat model (agent actions)

| Threat | Example | Control | Residual |
|---|---|---|---|
| Unauthorised tool use (OWASP ASI02) | A research agent calls `email.send` | Capability check against the configured profile → Block | None inside the boundary; enforcement is the caller's |
| Capability confusion | Present `data:read` for `data.write` | Claimed capability must equal the required one → Block | — |
| Self-granted privilege (ASI03) | Body adds `"capabilities": ["payment:execute"]` or `"approved": true` | Strict JSON → 400; grants only from configuration | — |
| Agent impersonation (ASI03) | Runtime A asks as the finance agent | Caller binding → Block | Within its own bound agents a runtime chooses the agent ID |
| Privilege-changing or critical action | `identity.grant`, `payment.execute`, `secrets.read`, `data.delete` | Critical → Block for every agent | No approval path for critical actions (by design) |
| Unknown tool or action | `shell.exec`, `email.delete` | Unknown → Block, risk Critical | — |
| Goal hijack carried into actions (ASI01) | Injected input leads the agent to send data out | Input decision Block/Review is kept; `email.send` is High → Review | Only if the runtime reports the input decision; hijacked Low/Medium actions that the agent may perform are allowed |
| Name smuggling | Unicode look-alikes, casing, spaces, wildcards | Exact ASCII names, no normalisation → 422 | — |
| History or log poisoning | Made-up tool names carrying text or secrets | Closed vocabulary: unknown names recorded as unknown | The correlation ID may still be caller-chosen (bounded format) |
| History flooding | Many requests push input analyses out of the 1,000-record history | `Standard` rate limit per client | The history is shared by both kinds and bounded; the audit log keeps everything |
| Recording failure hides a decision | The activity store fails | Every sink tried, then 500 with no decision | — |
| Misconfiguration | Typo in a capability or client | Startup validation | A wrong but valid grant is the operator's decision |

## 11. Attack scenarios (tests)

`AgentAttackScenarioTests` (Security tests, reference catalogue) and `AgentActionAuthorizeEndpointTests` (HTTP):

| Scenario | Expected | Test |
|---|---|---|
| 1. Unauthorised tool | Block (`CapabilityNotGranted`) | `Scenario1_UnauthorizedTool_AnAgentWithNoCapabilityForTheTool_IsBlocked` |
| 2. Wrong capability (`data:read` → `data:write`) | Block (`CapabilityNotGranted` / `CapabilityMismatch`) | `Scenario2_WrongCapability_AnAgentWithDataReadRequestingDataWrite_IsBlocked` |
| 3. High-impact action with the capability | Review | `Scenario3_HighImpactAction_WithTheCapability_IsHeldForHumanReview` |
| 4. Safe read | Allow | `Scenario4_SafeRead_WithTheCorrectCapability_IsAllowed` |
| 5. Privilege escalation | Block | `Scenario5_PrivilegeEscalation_RequestingACapabilityTheAgentDoesNotPossess_IsBlocked`, `…BorrowingAnotherAgentsIdentity_IsBlocked` |
| 6. Unknown tool or action | Block | `Scenario6_UnknownToolActionOrAgent_IsBlocked_NeverSilentlyAllowed` |
| 7. Policy integrity (Block → Allow, Review → Allow) | Impossible | `Scenario7_PolicyIntegrity_*`, `AgentActionPolicyTests.Decide_WhatTheAgentClaims_CannotTurnBlockOrReviewIntoAllow`, `Authorize_AnyFieldBeyondTheContract_Returns400_SoTheAgentCannotAssertItsOwnAuthority` |

## 12. Not built (next)

Enforcement for tools other than the gateway's reference tool (Milestone 11 built the tool gateway, its argument policy
and signed single-use execution grants for `knowledge.lookup`), MCP and other tool integrations, argument-level policy
for other tools (recipients, amounts, paths, domains), screening of tool output and indirect prompt injection,
server-verified linkage between an action and the input's security event **at this endpoint** (the tool gateway has it
since Milestone 13, opt-in), an approval workflow for this endpoint's Review (the gateway has one since Milestone 13;
Critical is never approvable), memory and context protection,
inter-agent controls, per-agent rate limits, and persistence of agents or decisions.
