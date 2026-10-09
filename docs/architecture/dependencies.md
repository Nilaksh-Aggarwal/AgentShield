# Dependencies

Versions are pinned centrally in `Directory.Packages.props` (backend) and `package-lock.json` (frontend).
Versions below were verified against nuget.org / npm on 2026-09-29.

## NuGet

| Package | Version | Project | Why |
|---|---|---|---|
| Scrutor | 7.0.0 | Application | Opt-in convention registration (`AddMarkedServices`) on the built-in container |
| Microsoft.Extensions.DependencyInjection.Abstractions | 10.0.12 | Application | `IServiceCollection` for `AddApplication` |
| FluentValidation | 12.1.1 | Application | Request validators |
| Npgsql.EntityFrameworkCore.PostgreSQL | 10.0.3 | Infrastructure | EF Core provider for PostgreSQL |
| Microsoft.Extensions.Diagnostics.HealthChecks.EntityFrameworkCore | 10.0.12 | Infrastructure | `AddDbContextCheck` for readiness |
| Microsoft.Extensions.Caching.Memory | 10.0.12 | Infrastructure | `IMemoryCache` behind `ICacheService` |
| Microsoft.Extensions.Configuration.Abstractions | 10.0.12 | Infrastructure | `IConfiguration` in `AddInfrastructure` |
| Microsoft.Extensions.Options.ConfigurationExtensions | 10.0.12 | Infrastructure | Options binding |
| Google.GenAI | 1.22.0 | AI | Official Google Gen AI SDK for .NET (googleapis/dotnet-genai): Gemini `generateContent` with structured output, used only by `GeminiSecurityAnalyzer` (ADR 0013). Transitive: Google.Apis/.Auth/.Core 1.69.0, Newtonsoft.Json 13.0.3, System.Management 7.0.2, MimeTypes 2.5.2, Microsoft.Extensions.AI.Abstractions 10.6.0 (no known vulnerabilities, 2026-09-29) |
| Microsoft.Extensions.Http | 10.0.12 | AI | `IHttpClientFactory` typed client for the Gemini adapter |
| Microsoft.Extensions.Configuration.Abstractions, Microsoft.Extensions.Options.ConfigurationExtensions | 10.0.12 | AI | `Ai` options binding (already used by Infrastructure) |
| Serilog.AspNetCore | 10.0.0 | Api | Structured logging, request logging, console/file sinks, compact JSON |
| Swashbuckle.AspNetCore | 10.2.3 | Api | OpenAPI generation + Swagger UI |
| Microsoft.AspNetCore.Mvc.Testing | 10.0.12 | ApiTests, IntegrationTests, Evaluation (tooling, ADR 0017) | In-memory host |
| xunit / xunit.runner.visualstudio / Microsoft.NET.Test.Sdk / coverlet.collector | 2.9.3 / 3.1.4 / 17.14.1 / 6.0.4 | tests | Existing test stack (unchanged) |

Removed: `Microsoft.AspNetCore.OpenApi` (template default) — replaced by Swashbuckle to avoid two competing
document generators (ADR 0004).

API boundary (Milestone 5, ADR 0014) uses only the shared framework (`Microsoft.AspNetCore.App`): authentication
(`AuthenticationHandler`), authorization policies, rate limiting (`Microsoft.AspNetCore.RateLimiting` /
`System.Threading.RateLimiting`), CORS and SHA-256 from `System.Security.Cryptography`. **No package added.**

Deliberately **not** added yet: `Microsoft.AspNetCore.Authentication.JwtBearer` (no identity provider yet; API keys use
the built-in handler base), Redis or distributed rate-limiting packages (single instance; ADR 0014),
`Microsoft.Extensions.Http.Resilience` (AI calls are never retried; the AI circuit breaker is AgentShield's own, in
Infrastructure, ADR 0016), LangChain, Semantic Kernel, other provider SDKs, the deprecated `Google.Ai.Generativelanguage` and community
`GoogleGenerativeAI` packages,
`Microsoft.EntityFrameworkCore.Design` (no migrations yet), FluentValidation DI extensions (Scrutor already scans
validators), assertion libraries.

## npm (frontend)

| Package | Version | Why |
|---|---|---|
| react / react-dom | 19.3.0 | UI (existing) |
| @tanstack/react-query | ^5.104.0 | Server state: caching, retries, cancellation |
| react-router | ^8.4.0 | Routing (`createBrowserRouter`, `RouterProvider` from `react-router/dom`) |
| tailwindcss, @tailwindcss/vite | ^4.3.3 | Styling: Tailwind v4 CSS-first (`@import "tailwindcss"` + `@theme` tokens in `src/index.css`) compiled by the official Vite plugin; no `tailwind.config.*` |
| vite, typescript, eslint, typescript-eslint, eslint-plugin-react-* | existing | Tooling (existing) |
| vitest (dev) | ^5.0.3 | Test runner for the frontend (Milestone 8): the Vite toolchain the project already uses (supports Vite 8), TypeScript without extra transforms |
| @testing-library/react, @testing-library/dom (dev) | ^16.3.3, ^10.4.2 | Render components and query them by role and text, as a user finds them (supports React 19; `dom` is its required peer) |
| jsdom (dev) | ^29.1.1 | DOM for the tests. 29.x because 30.x requires Node 24.15 or later |

Deliberately not added: `@testing-library/user-event` and `@testing-library/jest-dom` (`fireEvent` and plain assertions
suffice), Playwright (the committed browser checks in `e2e/` use only Node and an installed Chrome or Edge, so no browser
download), Stryker for JavaScript. `npm install` reported 0 vulnerabilities after these additions (2026-10-01).

Deferred until the first real form: `react-hook-form`, `zod`, `@hookform/resolvers` (ADR 0007).

## .NET tools (dotnet-tools.json)

| Tool | Version | Why |
|---|---|---|
| dotnet-stryker | 5.0.0 | Mutation testing of the security core (Milestone 8; configs in `tests/mutation/`). A local tool, run on demand with `dotnet tool restore` and `dotnet stryker`: no project references it, so it adds nothing to the build or the application. Verified publisher on nuget.org; runs on the .NET 10 SDK (checked by running it) |
