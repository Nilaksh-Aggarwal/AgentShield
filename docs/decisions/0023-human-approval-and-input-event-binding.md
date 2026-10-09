# 0023 — Human approval for held tool calls, binding a tool call to its server-recorded input analysis, and the security-closure fixes of Milestone 13

- **Status:** Accepted — 2026-10-07 (Milestone 13)
- **Builds on:** [0020](0020-agent-action-authorization-boundary.md) (authorization boundary, unchanged),
  [0021](0021-tool-gateway-enforced-execution.md) (tool gateway, grants unchanged), [0019](0019-security-activity-history.md)
  (recording contract), [0014](0014-api-boundary-hardening.md) (permissions), [0022](0022-attack-lab-demonstration-layer.md)
  (Attack Lab). Changes no detector, threshold, risk rule, policy rule, AI, capacity or circuit setting.
- **Specification:** [tool-gateway.md](../security/tool-gateway.md) sections 16–18; invariants 74–81 in
  [security-invariants.md](../security/security-invariants.md).

## Context

After Milestone 11 a Review at the tool gateway was a dead end: the call was held and nothing could ever run it, so the
only safe answer for a high-risk action was "never". And the input decision the boundary weighs was still the caller's
report (`inputDecision`): an agent that had an input analysed and blocked could simply not say so. Both gaps were stated
limitations of the M11 and M12 reports. Milestone 13 closes them, plus three findings carried over: the intermittent
startup test failure X-05, a cancellation gap in the shared recording contract, and the reviews of grant scope (F7) and
agent identity at the M10 endpoint.

## Decision

### 1. Human approval: Review never becomes Allow by itself

1. **Where an approval comes from.** When the boundary's verdict is Review and the gateway could run the action (an
   argument policy exists), the gateway creates a **pending approval** (`ToolApproval`, Domain) bound to the exact call:
   the agent (from the key), the calling client, tool, action, the catalogue's capability, a SHA-256 digest of the
   arguments exactly as sent, and the referenced input event (if any), with the boundary's risk and reason and the input
   decision it was held under. Order: the `Reviewed` entry carrying the approval ID is recorded, then the approval is
   stored, then the `Rejected` entry is recorded; if that fails, the approval is withdrawn, so an approval exists only
   when the audit log holds the request that created it. The response is unchanged (`Review`, `HeldForReview`,
   `executed: false`) plus `approvalId`. A Review for an action no tool here runs gets no approval.
2. **Statuses** `Pending → Approved | Denied | Expired`, and `Approved → Used | Expired`. Pending and Approved expire at
   `requestedAt + ToolApprovals:LifetimeSeconds` (default 600, 1–86,400, validated at startup); expiry is computed from the
   clock on every read and check, not by a timer. Denied, Expired and Used are final.
3. **A person decides** through `POST /api/v1/agent/approvals/{id}/approve` or `/deny` (no body: nothing in the request can
   assert authority, a decision, a risk or a grant) and lists through `GET /api/v1/agent/approvals` (newest first, at most
   50, metadata only: never the arguments, their digest or a client). The decider is the authenticated client. The
   decision is recorded (`ToolApprovalEvent`, audit log event 1003, to every `IToolApprovalEventSink`) before it takes
   effect for anyone: the store reserves it (`TryBeginDecision`: the approval stays Pending, so nothing can use it, and
   any other decision is refused as already decided), the use case records it, then `CompleteDecision` makes it take
   effect. If recording fails or is cancelled, the approval is withdrawn and the request fails (500). (The first
   implementation committed first and recorded afterwards: D-22, fixed before release.) 400 for an ID that is not a
   GUID, 404 `Approval.NotFound`, 409 `Approval.AlreadyDecided` / `Approval.Expired`.
4. **New permission `agent:approve`** (policy `AgentApprove`, `Standard` rate limit). It grants nothing else and nothing
   else grants it. **Separation of duties:** outside Development a client holding `agent:approve` may hold neither
   `tool:execute` nor `agent:authorize` (startup fails), so an agent's credential can never approve its own calls. The
   public Development key holds all three for the demo; self-approval is therefore possible only in Development.
5. **Executing an approved call: the same gateway, no second path.** The agent re-submits the same call with `approvalId`.
   The gateway runs every stage again: the boundary decides afresh (a Block is never lifted and leaves the approval
   unused; an Allow runs without using it); for a Review it **atomically** uses the approval (`TryUse`: Approved, not
   expired, and the call presented equals the binding in agent, client, tool, action, capability, argument digest and,
   when presented, input event); anything else is `ApprovalRejected` (Block, nothing runs; the reason — not found, not
   approved, expired, used, or which binding field differs — goes to the audit log only). Then the argument policy and the
   grant as in ADR 0021. The execution authority issues a grant for a Review only if the approval is `Used` **by this very
   request's security event** and bound to this agent, client, tool, action and capability: it checks the store itself,
   not the gateway's word. The approved run's response is `Allow` / `Executed` with the boundary's reason (for example
   `HumanApprovalRequired`) and the approval ID.
6. **Store:** `IToolApprovalStore` (Application port), `InMemoryToolApprovalStore` (Infrastructure): one per process,
   bounded (1,000), every transition under one lock, open (Pending, Approved) approvals never evicted (when full of open
   approvals a new hold fails closed: 500, nothing runs). Not durable; a restart forgets every approval, which only ever
   means "not approved".

### 2. A tool call references the server's record of its input analysis

1. Every firewall analysis is recorded by `InputSecurityContextRecorder` (an `ISecurityEventSink`, so under the existing
   every-sink-then-fail-closed contract) into `IInputSecurityContextStore` (`InMemoryInputSecurityContextStore`, one per
   process, 10,000, 10 minutes): security event ID, correlation ID, the analysing client and the decision. No input,
   finding or reason is kept.
2. A gateway request may carry `inputEventId`. The gateway verifies it: the event exists, the same client analysed it, in
   the same trace (correlation ID), within 10 minutes. Anything else is `InputContextRejected` (Block, nothing runs; which
   check failed goes to the audit log only), whatever the boundary would have said.
3. The input decision the boundary weighs is the **strictest** of the verified event's decision, the decision recorded in a
   presented approval, and the caller's own `inputDecision`. So a caller can tighten but never replace the server's record:
   an input Block stays Block, an input Review stays Review (and needs an approval), an input Allow still needs the
   action's own authorization.
4. **Not enforced:** a caller that does not reference its input. Then the call is decided as before (the action, plus the
   caller's report, which only tightens). AgentShield cannot see which input an agent acted on; making the reference
   mandatory per agent is listed as NEXT.

### 3. Security-closure fixes

1. **X-05 (startup failure reported as `ObjectDisposedException`) — fixed.** Root cause: `Program.Main` ended with
   `app.RunAsync()`, which disposes the host when startup fails. With `WebApplicationFactory`'s minimal hosting, `Main`
   runs on its own thread; when the test thread attached to the host after that disposal (under load), it reported the
   disposed service provider instead of the `OptionsValidationException`. Reproduced deterministically by delaying the
   test host's attachment (1 s). Fix: `StartAsync`, `WaitForShutdownAsync`, and `DisposeAsync` only after a host ran; a
   host that never started is left to the process. No assertion and no timeout changed. Regression:
   `StartupFailureReportingTests` (4 rows; three delay the attachment by 1 s and fail on the old code).
2. **Recording under cancellation (Part 14) — fixed.** The shared contract "every sink, then fail closed" stopped at the
   first sink that threw `OperationCanceledException`, so a cancelled request could leave one sink holding an entry the
   others skipped. `EventSinks.PublishToEveryAsync` now tries every sink whatever another does, then raises a failure
   (one as itself, several as an aggregate) over a cancellation. Used by the firewall, the authorization boundary, the
   gateway and approvals. The gateway's post-execution entries (`GrantRefused`, `Completed`, and `Failed` as in D-21) are
   recorded with a token of their own.
3. **F7 (grant scope names the call, not the arguments) — no change.** The grant cannot carry other arguments: the gateway
   builds the call it presents from the arguments its own policy validated in the same request and presents that request's
   one grant once; grants never leave the process. An approval binds the arguments (digest), since it outlives the request.
   Pinned by `ToolGatewayApprovalTests.TheToolGetsExactlyTheArgumentsValidatedInTheSameRequest_UnderThatRequestsOneGrant`.
4. **M10 agent selection — documented, no change.** At the gateway the agent comes from the key (ADR 0021), so a runtime
   cannot pick another agent to run a tool. `POST /api/v1/agent/actions/authorize` still takes `agentId` (bound to its
   clients by D-20) and only decides; nothing executes on its answer, so it cannot be used to run a tool as another agent.

### 4. Console

The Agent security page lists held calls from the real store (`ApprovalsPanel`: agent, tool and action, risk, reason,
times, Approve / Deny for pending ones). Attack Lab T-04 is now "Held for a person's approval": the firewall holds an
uninspectable input for review, the lookup references that analysis in the same trace while claiming the input was
allowed, the gateway holds it; Approve → the agent re-submits with the approval and the lookup runs once; Deny or expiry →
nothing runs. Every status shown is the API's.

## Consequences

- One permission, three endpoints, two optional request fields (`inputEventId`, `approvalId`), one response field
  (`approvalId`), two outcomes (`InputContextRejected`, `ApprovalRejected`, both Block), one audit event (1003). Pinned
  inventories, OpenAPI documents, field sets and outcome tables updated deliberately.
- No new executable tool: `knowledge.lookup` is still the only one, so the approval flow runs real code end to end but
  the only approvable action is a read-only lookup held because of its input. A high-risk action with a real tool needs a
  new tool, its ADR and its effects (ADR 0021).
- Approvals and input records are process-local and in memory, like grants and the activity history. Multi-instance or
  durable approvals need their own ADR.
- **Not built:** approval routing, approver roles or quorum, notifications, delegation, editing a held call, durable
  approvals, mandatory input references, Agent Control Standard conformance.
