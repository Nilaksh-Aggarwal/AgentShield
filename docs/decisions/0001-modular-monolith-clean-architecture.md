# 0001 — Modular monolith with Clean Architecture

- **Status:** Accepted — 2026-09-29

## Context

A hackathon prototype that must be demo-ready quickly, yet credible as an enterprise security product whose security
decisions stay deterministic and testable.

## Decision

One deployable ASP.NET Core API, split into projects by responsibility: Domain ← Application ← (Infrastructure, AI,
Security) ← Api. Boundaries are enforced by project references. Application defines ports; outer projects implement
them; Api is the only composition root.

## Consequences

- Simple to run, debug and demo; no network boundaries between modules.
- The deterministic security core (`Security`) and AI adapters (`AI`) are separate projects, which makes "AI is not the
  final authority" structurally visible.
- No Redis, message brokers, microservices, event sourcing or mediator/CQRS framework until a real need is proven in a
  new ADR.
