# 0004 — Swashbuckle for OpenAPI

- **Status:** Accepted — 2026-09-29

## Context

The .NET 10 template ships `Microsoft.AspNetCore.OpenApi` (`AddOpenApi`) and no UI. The team wants Swagger UI, not
Scalar.

## Decision

- Use `Swashbuckle.AspNetCore` 10.x for both document generation (`/swagger/v1/swagger.json`) and UI (`/swagger`).
- Remove `Microsoft.AspNetCore.OpenApi` so only one generator describes the API.
- XML doc comments and `[ProducesResponseType]` metadata drive the document.
- `Api:SwaggerEnabled` unset (the default) = enabled only in the Development environment; an explicit value overrides
  the environment either way. The Development default comes from `IHostEnvironment`, not from
  `appsettings.Development.json`, so it does not depend on the content root (working directory).

## Consequences

One source of truth for the contract. Covered by `SwaggerTests`: the document is served, problem responses are
described, every routed controller action is documented, and the environment/configuration matrix holds (Development
without appsettings files, explicit disable, Production default, explicit enable).
