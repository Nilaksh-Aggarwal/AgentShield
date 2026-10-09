# agentshield-web

React 19 + TypeScript (strict) + Vite 8 frontend for AgentShield.

```bash
npm install
npm run dev      # http://localhost:5173 — proxies /api and /health to http://localhost:5102
npm run lint     # ESLint (type-aware)
npm run build    # tsc -b && vite build
```

Configuration: copy `.env.example` to `.env.local`. `VITE_*` variables are embedded in the public bundle — never put
secrets in them.

## Structure

```text
src/
  app/                   router (+ route error view), providers (TanStack Query), layouts (app shell: header,
                         primary navigation, footer, skip link, focus on navigation)
  features/<name>        api/ (calls apiClient), hooks/ (TanStack Query), model/ (pure presentation logic),
                         components/, index.ts (public surface)
  shared/components/ui      Button/ButtonLink, Card, Badge, StatusIndicator, SectionHeader, EmptyState, icons
  shared/components/layout  PageHeader (the page's h1), DocumentTitle, SkipLink
  shared/constants       runtime configuration
  services/api           the ONLY place that performs HTTP (ESLint bans fetch elsewhere)
```

Routes: `/` Overview (product introduction: capabilities, why layers, pipeline, AI safety, protections, limits),
`/analyze` Analyze, `/activity` Activity (history not enabled; says so, no numbers), anything else → Not found. Each
page renders one `PageHeader` (its only `h1`) and one `DocumentTitle`. `AnalysisPipeline` is the only pipeline
visualisation (`layout="rail"` on Analyze, `layout="wide"` on the Overview); stage wording lives in `pipelineStages`.
Product copy states implemented behaviour only: no metrics, no accuracy figures, no absolute claims.

Data flow: component → feature hook → feature API function → `apiClient` → backend.

## Presenting security results

`features/firewall/model` turns API values into plain language; components never show raw enum names as the main
text.

- Decisions: Allow → "Safe to forward", Review → "Hold for human review", Block → "Do not forward to the agent". Never
  claim an input is guaranteed safe. An unknown decision is presented as held for review, never as safe.
- Findings: `presentFinding` maps every known code to a title, description, source (Rules, AI-assisted for
  `*.AiDetected`, System for safeguards) and recommended action. Unknown codes fall back to a generic presentation
  (the API's own client-safe description) instead of breaking the UI.
- Confidence is a heuristic, not a probability: show "Rule confidence (heuristic)" / "AI-reported confidence
  (uncalibrated)" with a coarse level, never a percentage.
- Never show rule IDs, detector names, patterns, decoded or hidden content, prompts, model output or provider errors.
  The API does not return them; do not add them from elsewhere.
- The console displays the API's decision and never computes one: no thresholds, policy or detection logic in React.
  The risk scale draws the level ranges the API documents (`riskBands`); the highlighted level is always the API's.
- AI status is not part of the API (by design, ADRs 0012/0015/0016). `presentAiParticipation` shows only what the
  findings prove: AI findings present (completed), the safeguard finding (could not complete, held for review), or
  neither (off, found nothing, or, for a Block only, skipped). Never guess the cause of a failure.
- Errors: `presentAnalysisError` maps status and error kind to plain language (never server text), shows the
  correlation ID, and states `Retry-After` only when the API sent it. Field-level validation messages appear next to
  the text box.
- Pipeline stages and their results come from `pipelineStages` / `pipelineOutcomes`, read from a completed response.
  While an analysis runs, no stage is shown as finished.

`apiClient` unwraps `{ data, meta }`, sends `X-Correlation-ID`, applies timeouts/cancellation, and turns every failure
into an `ApiError` with a safe `userMessage`. Never render raw server errors.

See [API conventions](../../docs/api/conventions.md#frontend-client) and [ADR 0007](../../docs/decisions/0007-frontend-state-and-forms.md).

## Styling

Tailwind CSS v4 via `@tailwindcss/vite`, CSS-first: `src/index.css` holds `@import 'tailwindcss'`, the semantic
`@theme` tokens (`bg-surface`, `text-muted`, `text-danger`, …) and a few base rules. There is no `tailwind.config` file.
Use tokens rather than raw colours, and write class names out in full (no string-built `bg-${tone}`) so Tailwind can
find them. Status colours go through the shared `Tone` (`neutral`, `info`, `success`, `warning`, `danger`,
`critical`), and colour is never the only signal (badges always carry text). Motion stays minimal: colour transitions
only, and anything animated opts out under `prefers-reduced-motion` (`motion-reduce:`).
