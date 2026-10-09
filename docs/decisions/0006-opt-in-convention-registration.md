# 0006 — Opt-in convention registration with lifetime markers

- **Status:** Accepted — 2026-09-29. The `RegistrationStrategy.Skip` choice below is superseded by
  [0008](0008-convention-registration-keeps-every-implementation.md).

## Decision

- Scrutor scans each layer's assembly for classes implementing `IScopedService`, `ITransientService` or
  `ISingletonService`. It registers them against their other interfaces with that lifetime, using
  `RegistrationStrategy.Skip` so explicit registrations win.
- `AddApplication()` also scans FluentValidation validators.
- Anything that needs configuration, a special lifetime, keys, `HttpClient`, `DbContext` or framework setup is
  registered explicitly.

## Why markers rather than naming conventions

The registration intent and lifetime are visible on the class declaration itself, and nothing gets registered by
accident because of its name. Covered by `ConventionalRegistrationTests`.
