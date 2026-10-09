# 0019 — Security activity history: a bounded, in-memory read model of security events

- **Status:** Accepted — 2026-10-01 (Milestone 9, step 1)
- **Builds on:** [0005](0005-optional-persistence-until-first-entity.md) (persistence only when configured),
  [0010](0010-deterministic-firewall-pipeline.md) (security events, fail closed), [0014](0014-api-boundary-hardening.md)
  (permissions, rate limits). Changes no decision, detector, threshold or AI setting.

## Context

Every analysis already produced a `SecurityEvent` (decision, risk, findings, AI summary, identifiers; never the input),
written to the structured log by `LoggingSecurityEventSink`. That log is the audit trail, but nobody can browse it from
the console: the Activity page said "history isn't enabled". Milestone 9 starts turning AgentShield into a security
gateway with an operations view, and the first piece is a history of recent decisions.

ADR 0005 expected security events to become the first persisted feature. Doing that now would make PostgreSQL
mandatory (migrations, a required connection string, Testcontainers tests), and the API would no longer run on a demo
machine without a database. The prototype needs a recent-activity view, not durable retention.

## Decision

1. **A read model, not a second audit trail.** `SecurityActivityRecord` (Application) is what the history keeps of a
   `SecurityEvent`: security event ID, correlation ID, time, kind (`InputAnalysis`), decision, risk (score and level),
   findings as code, category and severity, and a coarse AI status (`Disabled`, `Completed`, `NotNeeded`, `Incomplete`).
   It is built only by `SecurityActivityRecord.FromSecurityEvent` (private constructor). It has no field for input,
   decoded content, prompts, provider output, rule IDs, detector identities, descriptions, input length or timing, and
   every AI failure (timeout, outage, rate limit, open circuit, capacity, invalid or refused answer) is `Incomplete`: the
   reason stays in the audit log, as before, so the history cannot be used to probe the analyser.
2. **Recorded from the final decision, through the existing port.** `SecurityActivityRecorder` is a second
   `ISecurityEventSink`. The analyze use case now publishes the one event it builds after the policy engine decided to
   *every* sink (`IEnumerable<ISecurityEventSink>`, as for detectors, ADR 0008), so a sink sees only the finished event
   and cannot change the decision. The record copies the decision and risk; no score, level or decision is computed
   again.
3. **Failure fails closed and costs no other sink its record.** The use case gives the event to every sink even when one
   throws, then raises the failure (one exception as itself, several as an `AggregateException`). The caller gets 500
   and no decision, never an Allow, exactly as the sink contract already required ("a failure to record is not
   swallowed"). The audit log still records the event, whichever sink failed. The global handler logs the failure as
   redacted text; the response carries none of it.
4. **Storage: in process memory, bounded, behind a port.** `ISecurityActivityStore` (Application) has two operations:
   append and a filtered, paged query. `InMemorySecurityActivityStore` (Infrastructure, singleton) keeps the most recent
   1,000 records in a fixed ring (oldest dropped first) and answers newest first in the order recorded. One lock guards
   the ring; filtering runs on a copy. Not durable: lost on restart, one history per process. A persistent store
   replaces it behind the same port without touching the recorder or the query; the recorder is already scoped so a
   `DbContext`-based store needs no lifetime change.
5. **Read API: `GET /api/v1/activity`.** Query parameters: `page` (1–100,000, default 1), `pageSize` (1–100, default 25),
   `decision` (repeatable: `Allow`, `Review`, `Block`), `minRiskLevel` (`Low` to `Critical`). Filters are bound as text
   and accepted only as exact names (422 otherwise), like JSON enums (ADR 0009): the query-string enum binder would also
   take `3`, `block` and `Block,Allow`. A value of the wrong type is a 400 that names the field and, since this ADR,
   never quotes the value (D-19). The response is the usual envelope with `items`, `page`, `pageSize`, `totalCount` and
   `totalPages`; items are mapped field by field, so a field added to the record is not returned by accident.
6. **Access.** A new permission `activity:read` (policy `ActivityRead`). It is an operator permission: the history shows
   every client's analyses, so firewall clients (`firewall:analyze`) do not get it, and it grants nothing else. The
   public Development client holds both, so the local console can show the page. Reads use the `Standard` rate limit.
7. **Console.** The Activity page lists the events (time, decision, risk, top finding, AI status), filters by decision,
   pages, and opens a row to its trace IDs. It renders only contract fields, never echoes an unknown AI status, shows an
   unknown decision as held for review, and states what the history keeps and for how long. No chart library.

## Consequences

- The Activity page shows real data. Each analysis costs one more in-memory append; reads cost at most one pass over
  1,000 records.
- **Not an audit guarantee.** The history is a convenience view. The security-event log stays the audit record, with its
  known limit (H-07: a sink failing inside Serilog loses the entry silently). Restarting the API empties the history;
  several instances have several histories.
- Offset paging over a live, bounded history: new events shift pages, and an old page can empty when records are
  dropped (the console offers the first page).
- The correlation ID shown may be chosen by the calling client (the API accepts at most 64 characters of
  `[A-Za-z0-9._:-]`); it is shown as text.
- **Later: persistence.** A follow-up ADR, as ADR 0005 foresaw: an EF Core entity mapped from `SecurityActivityRecord`
  (same fields), a migration, a required connection string in the environments that persist, Testcontainers tests,
  retention and deletion rules, and a decision on whether a store failure should still fail the analysis.
- **Later: agent events.** `SecurityActivityKind` is the extension point for the Agent Firewall milestone (agent decision,
  tool call, tool result, final action). Each new kind needs its own pipeline that produces a decided `SecurityEvent`
  first; the history records it the same way and stays metadata only (no tool parameters, no tool output). Nothing of
  this exists yet.
