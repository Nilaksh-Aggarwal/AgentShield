# 0021 — Tool gateway: enforced execution behind the authorization boundary, credential-bound agent identity, argument policy, signed single-use execution grants

- **Status:** Accepted — 2026-10-07 (Milestone 11)
- **Builds on:** [0020](0020-agent-action-authorization-boundary.md) (the authorization boundary, unchanged),
  [0019](0019-security-activity-history.md) (activity history), [0014](0014-api-boundary-hardening.md) (permissions,
  rate limits), [0009](0009-strict-json-input.md) (strict JSON). Changes no detector, threshold, AI or capacity setting,
  and no rule of the M10 policy.
- **Specification:** [tool-gateway.md](../security/tool-gateway.md).

## Context

Milestone 10 made AgentShield a **decision point**: it decides whether an agent may perform a tool action, but the caller
executes the tool, so a runtime that does not ask, or ignores the answer, bypasses it. ADR 0020 listed five bypasses:
(1) the caller can execute anyway; (2) a runtime chooses the agent ID among its bound agents; (3) the reported input
decision is not tied to the input's security event; (4) tool arguments are not checked; (5) an Allow is not a signed,
single-use authorization. OWASP's agentic guidance (ASI02, ASI03) centres on mediating every tool call and keeping tool
credentials away from the agent. A general tool platform, MCP or real tools would be premature; the enforcement
architecture has to be proven first, with one tool that cannot hurt anything.

## Decision

1. **AgentShield executes, behind the boundary.** `POST /api/v1/agent/tools/execute` (`AgentToolsController`, permission
   `tool:execute`, policy `ToolExecute`, `Standard` rate limit) asks the tool gateway (`IToolGateway`, Application) to
   run a tool action. The gateway runs it only on the M10 boundary's Allow and returns the outcome in a 200 whatever it
   decided. One reference tool exists: `knowledge.lookup` (capability `knowledge:read`, effect `ReadOnly`, risk Low), an
   exact lookup in a ten-topic dataset compiled into the binary. It has no I/O of any kind.
2. **The agent is the credential.** A request names no agent (an `agentId` field is a 400). Each agent may have a
   `GatewayClient` (`AgentAuthorization:Agents:{id}:GatewayClient`): the API client whose key *is* that agent at the
   gateway. Startup validation makes the mapping a bijection between `tool:execute` clients and gateway agents (every such
   client identifies exactly one agent; no client identifies two; the gateway client is one of the agent's `Clients`, so
   the boundary's caller binding holds). Holding one agent's key gives that agent's grants and no other's. The smallest
   mechanism that closes bypass 2 without a new authentication scheme; the authentication handler is unchanged.
3. **One policy, consumed, not copied.** The gateway asks `IAgentActionAuthorizer` exactly as M10 does (the request's
   tool, action, claimed capability and optional input decision, with the caller from authentication and the agent from
   the caller). Review and Block end there, as decided. Only an Allow reaches the gateway's own checks, and each of them can
   only turn it into a Block: **an executable tool** (an argument policy and an executor for the action; otherwise
   `ToolUnavailable`) and **the action's argument policy** (otherwise `ArgumentsRejected`). There is no second policy
   engine; High stays Review and Critical stays Block even when an executor exists (tested with test-only executors for a
   Medium, two High and a Critical action).
4. **Argument policy per tool, small and explicit.** `IToolArgumentPolicy` (Security) turns the untrusted JSON object into
   the action's typed, validated `ToolArguments`. For `knowledge.lookup`: exactly one member `query`, a string of 1–200
   characters, not only whitespace, without control characters, well-formed UTF-16; names exact; a repeated `query` is
   rejected even where a parser would allow it. The value object `KnowledgeLookupArguments` enforces the same schema in its
   constructor, so a tool cannot receive arguments outside it. No generic policy language. The request validator (422)
   only requires `arguments` to be a JSON object.
5. **Execution grants: signed, bound, single use, short-lived.** On an Allow that passed the gateway's checks, the
   execution authority (`IToolExecutionAuthority`, `ExecutionGrantAuthority` in Security) issues an `ExecutionGrant`:
   execution ID (UUIDv7), scope (security event, correlation ID, agent, tool, action, capability), issued-at, expires-at
   (30 s) and an HMAC-SHA256 signature over all of it. Before issuing, **the authority asks the boundary again** and issues
   nothing it does not allow; the grant has no decision field. Executing, it verifies the signature (constant time),
   consumes the grant from its ledger atomically (exactly one of any number of concurrent presentations wins), rejects it
   when expired, and checks it against the call the gateway presents, which the gateway builds from its own request: wrong
   agent, tool, action, capability or request → no execution (the grant is burnt). The key is 256 random bits generated in
   memory per process: never configured, logged, returned or exported. Grants never leave the process: the request has no
   field that could carry one (400) and the response returns only the execution ID, an audit identifier. Ledger bounded to
   4,096 outstanding grants (expired ones purged on issue; beyond the bound → 500, never an eviction). Local and
   per-process by design; a restart invalidates every grant.
6. **Complete mediation by construction.** `IToolExecutor` (one per executable action, Infrastructure) may be held only by
   the execution authority; the authority only by the gateway; the gateway only by `AgentToolsController`. Pinned by a
   reflection test over every type in every AgentShield assembly, an endpoint inventory test (one endpoint requires
   `ToolExecute`, nothing else lives under the tools route) and composition tests (one executor, internal and sealed, not
   resolvable as itself; one policy per executor; both in the catalogue). The tool decides nothing about who may call it.
7. **Credential boundary.** The agent holds only its AgentShield API key, which lets it *ask*. The execution authority
   holds execution authority (the signing key, the ledger and the only references to the tools). The tool runs only when the
   authority ran it for a verified, consumed grant.
8. **Every stage recorded before the next.** `ToolGatewayEvent` (Domain) is a small lifecycle state machine:
   `ToolAuthorizationRequested` → `ToolAuthorizationAllowed` / `ToolAuthorizationBlocked` / `ToolAuthorizationReviewed` →
   (`ToolExecutionStarted` → `ToolExecutionCompleted` / `ToolExecutionFailed` / `ToolExecutionRejected`) or
   `ToolExecutionRejected`. Transitions out of order and outcomes that disagree with the boundary's decision cannot be
   built. Each entry goes to every `IToolGatewayEventSink` (audit log event 1002, `agentshield.tool_gateway_events`
   metric by stage; activity history) before the gateway goes on: a recording failure → 500 with no decision and no result,
   so a grant is never issued before the request was recorded and a tool never runs before its start was. Each outcome
   has exactly one decision (`ToolExecutionOutcomes.DecisionFor`); only an invoked tool is an Allow.
9. **Activity: one record per request, no kind per stage or decision.** New kind `SecurityActivityKind.ToolExecution`,
   recorded from the request's last entry, with `toolExecution` = outcome, executed, execution ID; the recognised agent,
   tool, action, capability and the boundary's reason as for agent actions. The audit log keeps the stages, the argument
   rule that was broken and why a grant was refused. Neither keeps the arguments or the tool's result. (ADR 0020's "no
   activity kind per decision" holds: the spec's seven event names are the audit log's stages, not activity kinds.)
10. **Input decision unchanged.** The optional `inputDecision` still only tightens and is still the caller's report
    (bypass 3 stays open, section 10 of the specification).

## Consequences

- AgentShield is an **enforcement point for the tools it executes**: for `knowledge.lookup`, no path inside AgentShield
  runs the tool without an Allow, and the agent holds no credential that runs it. Every other tool is still decided,
  not enforced (the caller executes it), until it is moved behind the gateway.
- The reference catalogue grows by one action (16 actions, 15 capabilities; pinned tests updated deliberately). The
  Development `research-agent` holds `knowledge:read`, and the public Development client gains `tool:execute` and is
  research-agent's gateway identity (Development only). Production configures no agent and no client, so the gateway
  answers 401 to everyone until an operator configures one.
- The activity read model changes shape (a deliberate privacy decision): items gain `toolExecution` (`null` for the other
  kinds). Pinned field-set tests updated.
- The agent directory validator accepts a client holding `tool:execute` (not only `agent:authorize`) among an agent's
  `Clients`; its message changed accordingly.
- **Not built:** out-of-process tool servers (where the grant would cross a process boundary and need a shared or
  asymmetric key and replay storage), MCP, real tools, an approval workflow for Review, verified linkage of the input
  decision to the input's security event, tool-output screening, per-agent rate limits, distributed grant state.
