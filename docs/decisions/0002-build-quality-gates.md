# 0002 — Build quality gates

- **Status:** Accepted — 2026-09-29

## Decision

- `Directory.Build.props` applies to all projects: `Nullable`, `AnalysisLevel=latest`, `AnalysisMode=Recommended`,
  `EnforceCodeStyleInBuild`, `TreatWarningsAsErrors`.
- `Directory.Packages.props` centralises NuGet versions.
- `nuget.config` restores from nuget.org only. A machine-wide second feed triggered NU1507 under central package
  management; single-source restore also avoids dependency confusion.
- `global.json` requires a .NET 10 SDK.

## Documented exceptions

| Rule | Scope | Reason |
|---|---|---|
| CA2007 (ConfigureAwait) | all | ASP.NET Core has no SynchronizationContext |
| CA1848 (LoggerMessage) | suggestion | Message templates are mandatory (CA2254 stays on); source-generated logging is recommended for hot paths |
| CA1716 (keyword names, e.g. VB `Error`) | all | C#-only codebase |
| CA1000 (static members on generic types) | `Result<T>` | Static factories are the intended API |
| CS1591 (missing XML docs) | Api | XML docs feed Swagger but are not required on every member |
| CA1707 / CA1515 / CA1054 / CA1056 / CA2234 | tests | Test naming and URI literals |
| CA1822 | `ContractProbeController` (test) | MVC actions must be instance methods |
| NU1901–NU1904 | warning, not error | New advisories must be triaged but must not break a demo build |

## Consequences

Warnings cannot accumulate. Any new suppression needs a justification in `.editorconfig` or `[SuppressMessage]`.
