# 0008 — Convention registration keeps every implementation

- **Status:** Accepted — 2026-09-29
- **Supersedes:** the `RegistrationStrategy.Skip` part of [0006](0006-opt-in-convention-registration.md). The lifetime
  markers and the opt-in model of 0006 are unchanged.

## Context

`AddMarkedServices` used Scrutor's `RegistrationStrategy.Skip`, which is `TryAdd` **by service type**: once an interface
had any registration, every further implementation of it was silently dropped. The firewall will resolve
`IEnumerable<IThreatDetector>` over several detectors (prompt injection, encoded payloads, secret extraction, …). With
`Skip`, only the first detector found by the scan would have run, and an explicitly registered detector would have
hidden all convention ones. No error, no log line: a detection gap you can't see.

Scrutor's other built-in strategies don't fit either. `Append` duplicates an implementation that is scanned twice or
also registered explicitly, and lets the convention override an earlier explicit registration. `Replace` removes
explicit registrations.

## Decision

`AddMarkedServices` uses `ConventionRegistrationStrategy` (Application, internal). For a convention registration
(service `S`, implementation `I`):

1. **No duplicates.** If `I` is already registered for `S` (by the convention or explicitly, any lifetime), nothing
   is added. An explicit registration of a marked class keeps its explicit lifetime.
2. **Every implementation is kept.** Otherwise the registration is added, so all implementations resolve through
   `IEnumerable<S>`.
3. **Explicit registrations win single resolution.** The registration is inserted *before* the first explicit
   registration of `S`, so the explicit one stays last. Microsoft DI resolves the last registration for
   `GetService<S>()`, so the explicit one wins whether it was made before or after the scan.

A registration counts as "convention" when it is exactly what the convention produces: a type registration of a
marked class with its marker's lifetime. Factory and instance registrations always count as explicit.

## Consequences

- Overriding a single service explicitly still works, but the marked implementation remains in `IEnumerable<S>`. To
  exclude a class entirely, remove its marker (and register what you need explicitly).
- Several convention implementations of the same interface, across layers and lifetimes, are all resolved.
- Covered by `ConventionalRegistrationTests` (UnitTests, descriptor rules) and `ConventionalResolutionTests`
  (IntegrationTests, the real container: `IEnumerable<T>`, lifetimes, explicit + convention detectors). With `Skip`
  restored, 6 of those tests fail.
