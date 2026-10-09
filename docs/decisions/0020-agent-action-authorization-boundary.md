# 0020 — Agent action authorization boundary: capabilities, effect-based risk, deterministic policy, decide-only

- **Status:** Accepted — 2026-10-07 (Milestone 10)
- **Builds on:** [0010](0010-deterministic-firewall-pipeline.md) (deterministic policy, fail closed),
  [0014](0014-api-boundary-hardening.md) (permissions, rate limits), [0019](0019-security-activity-history.md) (activity
  history, `SecurityActivityKind`). Changes no detector, threshold, AI or capacity setting.
- **Specification:** [agent-action-authorization.md](../security/agent-action-authorization.md).

## Context

AgentShield screens the *input* of an AI application. The next risk surface is what an agent *does*: OWASP's Top 10 for
Agentic Applications (2026) puts Agent Goal Hijack (ASI01), Tool Misuse and Exploitation (ASI02) and Identity and
Privilege Abuse (ASI03) first, and its guidance centres on restricting tool calls and enforcing authorization boundaries
for agent actions. Building a tool runtime, MCP integration or real tools now would be large and premature; the
security control layer has to exist first, and it must not depend on the model's judgement.

## Decision

1. **Decide, never execute.** `IAgentActionAuthorizer` (Application port, implemented in Security) takes an
   `AgentActionRequest` and returns Allow, Review or Block with a coarse reason and the action's risk. It executes nothing.
   AgentShield has no tool executor; only `Allow` permits execution, and enforcing that is the caller's job until a tool
   gateway exists. Exposed as `POST /api/v1/agent/actions/authorize` (200 whatever the decision).
2. **Trusted data, untrusted proposal.** Agents (granted capabilities, bound API clients) come from configuration
   (`AgentAuthorization:Agents`, Infrastructure, validated at startup, immutable). Tool actions (required capability,
   declared effects) come from a fixed reference catalogue in code (Security), pinned by tests: each entry is security
   policy. The request carries the agent, tool, action, the claimed capability and an optional input decision — nothing
   else: no tool arguments (a policy that does not read them cannot vouch for them), no decision, risk, grants or
   reasoning (strict JSON → 400). Names are exact lower-case ASCII; nothing is normalised (look-alikes and casing → 422).
3. **Capabilities, not tool names.** Each action has exactly one required capability; capabilities are exact names
   without wildcards. The checked capability is the catalogue's, held only if the profile holds it; the claimed one must be
   equal to it (`CapabilityMismatch` otherwise).
4. **Caller binding.** Each agent lists the API clients that may act for it; the caller comes from authentication. Holding
   `agent:authorize` does not let one runtime speak for another runtime's agent (`CallerNotBoundToAgent`). Found while
   designing the integrity tests: without it, any authorizing client could borrow any agent's grants.
5. **Risk from declared effects.** `ActionEffects` (read-only, metadata, modifies data, draft for approval, external
   communication, modifies sensitive data, privileged operation, financial, credential access, destructive, privilege
   change) map to Low / Medium / High / Critical; an action is as risky as its worst effect. No AI, no score, no name
   matching. No effect is invalid; an unknown action is Critical.
6. **Ordered, deterministic policy.** Unknown agent, unbound caller, unknown tool, unknown action, capability mismatch,
   capability not granted, Critical risk, input Block → Block; High risk, input Review → Review; otherwise Allow. All Block
   rules precede all Review rules, so the decision is monotone in every fact. **Critical actions are denied to every
   agent**, granted or not: no approval workflow exists that could release them safely. Each reason has exactly one
   decision (derived in the domain), so reason and decision cannot disagree.
7. **The input decision is evidence that can only tighten.** The caller may report the firewall's decision on the input
   behind the action; Block and Review carry over, Allow or absence adds nothing. It is not verified against AgentShield's
   own records (a later step).
8. **Recorded like every security decision.** An `AgentActionEvent` goes to every `IAgentActionEventSink` after the
   decision: the audit log (event 1001, covered by the startup log-level check) and the activity history as
   `SecurityActivityKind.AgentActionAuthorization`. A sink failure → 500 and no decision, after the other sinks recorded.
   Only recognised names are recorded; made-up names become `null`/`(unknown)`. No kind per decision (the record's decision
   says it).
9. **Access.** New permission `agent:authorize` (policy `AgentAuthorize`), separate from `firewall:analyze` and
   `activity:read`; `Standard` rate limit (a decision is cheap, no AI). The public Development client holds it in
   Development only, for the console's preview; no other client gets it implicitly.

## Consequences

- The activity read model changes shape (a deliberate privacy decision): `risk.score` may be `null`, `aiAnalysis` may be
  `null`, and items gain `agentAction` (`null` for input analyses). Its pinned field-set tests were updated.
- Production configures no agent, so every agent action is blocked until an operator adds agents and binds them.
- The boundary is enforceable inside AgentShield — nothing an agent sends lowers a decision — but **not over execution**:
  a runtime that does not ask, or ignores the answer, bypasses it. Agent identity within a client's bound agents, the
  input decision and the absence of argument checks are further limits (specification, section 9).
- **Later:** a tool gateway or MCP proxy that holds tool credentials and executes only on Allow; argument-level policy;
  verified linkage to the input's security event; signed single-use decisions; an approval workflow (which could move
  Critical to Review); a catalogue fed by tool registration with declared effects; tool-output screening.
