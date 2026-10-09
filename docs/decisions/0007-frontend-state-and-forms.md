# 0007 — Frontend state and forms

- **Status:** Accepted — 2026-09-29

## Decision

- Server state: TanStack Query. Local UI state: React state/context. No Redux or other global store until a real
  requirement appears.
- Routing: React Router 8 data router (`createBrowserRouter`).
- All HTTP goes through the central `apiClient`; ESLint `no-restricted-globals` bans `fetch` elsewhere.
- Forms: React Hook Form + Zod is the chosen stack for complex forms, **installed with the first real form** (package
  discipline: no unused dependencies). Frontend validation is UX only; backend validation is authoritative.

## Consequences

The dependency surface stays minimal today. The analyze form in the next milestone adds `react-hook-form`, `zod` and
`@hookform/resolvers`.
