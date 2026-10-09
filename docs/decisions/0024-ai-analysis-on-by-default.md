# 0024 — AI-assisted analysis on by default

- **Status:** Accepted — 2026-10-09.
- **Amends:** [0013](0013-gemini-provider.md) (Gemini provider), which kept AI analysis off by default.
- **Unchanged:** [0012](0012-ai-analysis-boundary.md), [0015](0015-ai-capacity-gate.md),
  [0016](0016-ai-provider-circuit-breaker-and-input-token-budget.md): AI only adds findings, the deterministic risk and
  policy engines decide, and every failure of an expected AI analysis holds the input for review.

## Context

The project owner requires Gemini AI-assisted analysis to be on in the normal application configuration and the
demonstration setup. The deterministic rules alone miss most paraphrased and non-English attacks (reliability
evaluation, `tests/Evaluation/reliability/results/report.md`), and AI-assisted analysis is the layer designed to catch
them. Until now `Ai:Enabled` was `false` in both appsettings files and AI had to be turned on explicitly.

The key cannot be committed. ADR 0013's startup validation already refuses `Ai:Enabled = true` without a key ("Gemini
API key is missing"), and a test pins it. Someone cloning the repository has no key.

## Decision

1. **`Ai:Enabled` is `true`** in `appsettings.json` and `appsettings.Development.json`. Provider (`Gemini`), model
   (`gemini-3.8-flash`), timeout, capacity and circuit-breaker settings are unchanged.
2. **No key, no start.** The startup validation is unchanged: with AI on and no `Ai:Gemini:ApiKey` the API refuses to
   start with a clear message. It never silently runs without AI.
3. **Running without AI is explicit and visible.** It needs `Ai__Enabled=false`, or the launch profile whose name says
   so, `http-deterministic`. The `http` and `https` profiles keep the default. A test pins both profiles.
4. **Tests and tooling stay offline.** Every test factory, the browser checks and the evaluation runner set
   `Ai:Enabled=false` and a blank key, or use a fake transport. Real-provider calls stay opt-in (`scripts/gemini-smoke.ps1`,
   the evaluation runner's `final`).
5. **The decision boundary is unchanged.** Gemini contributes findings from the closed catalogue; the deterministic
   risk and policy engines decide Allow, Review or Block; AI never authorizes a tool action; every AI failure holds the
   input for review.

The alternatives were rejected:
- **Start without a key and hold every non-blocked input for review.** Every benign input would show Review, a misleading
  demonstration.
- **Start and decide on the rules alone.** This contradicts ADR 0016: an unavailable provider must never mean
  deterministic-only.

## Consequences

- **A key is needed by default.** A clone runs with AI only after a key is set in User Secrets, or deterministically with
  the named profile. The README Quick Start says so.
- **Content leaves the process by default.** Inputs the rules do not block are sent to Google, after the disclosure
  policy masks secrets. On the free tier Google may use them, so use demo content only.
- **Capacity applies to everyday use.** `DefaultClient` allows 4 AI analyses per minute per client; more are held for
  review (`CapacityExceeded`), never allowed.
- **Outages hold traffic.** If Gemini is unavailable, every input the rules do not block is held for review until the
  circuit closes. This is measured in the reliability report's simulated-outage runs.
- **Production needs a key or an explicit off.** Production would need `Ai__Gemini__ApiKey` or an explicit
  `Ai__Enabled=false`. No production deployment or secret was changed.
