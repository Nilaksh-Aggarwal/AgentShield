# 0003 — Result pattern, centralised HTTP mapping, Problem Details

- **Status:** Accepted — 2026-09-29

## Decision

- Expected failures are values: `Result` / `Result<T>` carrying one or more `Error(Code, Message, Type, Metadata)`.
  Unexpected failures are exceptions, handled once by `GlobalExceptionHandler`.
- `Result` and `Error` are framework-independent and contain no HTTP concepts.
- The API maps results in one place (`ResultActionResultExtensions`, `ErrorStatusCodes`, `ProblemActionResult`).
- Success bodies use `{ data, meta }`. Errors use RFC 9457 Problem Details via ASP.NET Core's native
  `AddProblemDetails` / `IProblemDetailsService` / `ProblemDetailsFactory`, customised once to add `correlationId`,
  `timestamp` and `errorCode`.
- A security decision (BLOCK etc.) is data in a 200 response, not an HTTP error.

## Consequences

- Controllers contain no status-code branching.
- Clients branch on `errorCode`, never on `detail` text.
- `[Produces]` must not be used at controller level: it rewrites Problem Details content types to `application/json`.
  This was found and fixed during the foundation work and is covered by ApiTests.
