# 0005 — Persistence activates only when configured

- **Status:** Accepted — 2026-09-29

## Context

PostgreSQL + EF Core is the chosen store, but no feature persists data yet, and demo machines may not run PostgreSQL.

## Decision

- Infrastructure contains `AgentShieldDbContext` (schema `agentshield`, no entities), the Npgsql provider and a
  `postgresql` readiness check.
- They are registered only when `ConnectionStrings:AgentShield` is set. Otherwise a startup warning is logged and
  readiness ignores the database.
- No EF retry strategy: retries are opted into per idempotent operation.
- No speculative entities or migrations.

## Consequences

- The API runs anywhere for demos. Liveness never depends on the database (tested).
- When the first persisted feature (security events) lands, a follow-up ADR should make the connection string
  required, add migrations (`Microsoft.EntityFrameworkCore.Design`) and add Testcontainers-based tests.
