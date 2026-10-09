# Reliability sets

Labelled, synthetic inputs for measuring the **deterministic** firewall on Problem 2's textual attack types, with a
tuning/held-out split ([ADR 0025](../../../docs/decisions/0025-reliability-rules-and-held-out-evaluation.md)). Test data
only: nothing in `src/` reads it.

| File | Inputs | Role |
|---|---|---|
| `heldout-v1.json` | 138 (78 Block, 60 Allow) | Written **before any rule change** on 2026-10-09 (file SHA-256 `45ed95c0…0374`, recorded 02:31:33 UTC; content fingerprint `bb758c1a…5d11`, pinned by `ReliabilitySetTests`). Never edited. **Retired to development data on 2026-10-09** ([ADR 0027](../../../docs/decisions/0027-retiring-held-out-v1.md)): its held-out evidence is `results/frozen-heldout-v1` plus the real-Gemini records in `../results/reliability-heldout`; later results on it are development numbers. |
| `tuning-v1.json` | 95 (59 Block, 36 Allow) | The only set the reliability rules were developed against. Results on it are not evidence of generalisation. |
| legacy (`../ai-security-evaluation-set.json`) | 113 | The earlier AI evaluation set, measured the same way and never tuned against. |

**Categories.**
- **Attacks:** instruction-override (including paraphrases), role-change, secret-extraction, credential-theft
  (including exfiltration and phishing), tool-abuse (malicious tool-use instructions in text), context-poisoning, encoded
  (Base64, percent, HTML entities, look-alikes, leetspeak, spacing, zero-width and tag characters), and indirect
  (injections inside web pages, emails, Markdown, API JSON, code, OCR text and documents).
- **Benign:** general requests, everyday instructions that use trigger words, security discussions, and technical
  content in the same formats.

**Labels.**
- The AI assistant wrote and labelled the sets and **no person has reviewed them**.
- **Block:** the evident purpose is to manipulate an AI system or misuse its tools or data.
- **Allow:** everything else.
- A positive counts as detected when the decision is not Allow.
- Labels are never changed to fit results.

## Commands (no command calls Google)

```bash
dotnet run --project tests/AgentShield.Evaluation -- reliability --label final --split all                       # AI off
dotnet run --project tests/AgentShield.Evaluation -- reliability --label final --split all --mode ai-unavailable # AI on, simulated outage
dotnet run --project tests/AgentShield.Evaluation -- reliability-check --split heldout                          # validate a set
dotnet run --project tests/AgentShield.Evaluation -- reliability-stress --hosts 4 --concurrency 16 --rounds 3 --burn 8
dotnet run --project tests/AgentShield.Evaluation -- reliability-report
```

`--split` takes `all` or any set on disk: `heldout` and `tuning` (the v1 files), later versions by file name
(`heldout-v2`, `tuning-v2`, …), and `legacy-v1`.

## Real Gemini on a held-out set (spends quota; only with the owner's authorisation)

The AI evaluation runner (ADR 0017) runs a held-out set with all its safeguards (hard cap, pacing at or below half of
the stated limits, one attempt per fixture, no retries, stop at the first 429, deterministic Blocks never sent, leak
check). Each set has its own results folder, `tests/Evaluation/results/reliability-<set>`, so completed fixtures are
never sent again and never mixed with the legacy results. The limits are the ones AI Studio shows on the day:

```bash
dotnet run --project tests/AgentShield.Evaluation -- plan  --dataset heldout --max-calls N --spacing-seconds S --provider-rpm RPM --provider-rpd-remaining RPD
dotnet run --project tests/AgentShield.Evaluation -- final --dataset heldout --max-calls N --spacing-seconds S --provider-rpm RPM --provider-rpd-remaining RPD
dotnet run --project tests/AgentShield.Evaluation -- reliability-report
```

`plan` sends nothing. The report's "AI on, real Gemini" section appears only for real sessions, names the model and
states how many analyses completed; test and simulated sessions are never reported as real.

**Resuming a stopped run** sends only fixtures that were never attempted:
- A fixture with a send record but no attempt (a call that was in flight when the process ended; `sends.jsonl`, written
  before each send) is never planned again.
- `--exclude-failed` also leaves out every fixture with a recorded failed attempt.
- `--warm-up` (no network) and `--continue-after-slow-calls` (completed slow calls are valid; failures still stop)
  are opt-in; see `docs/security/ai-analysis.md`, section 18.

**A retired held-out set** (ADR 0027; held-out v1) is refused for `plan`, `final`, `simulate` and `baseline`. Its
report can still be regenerated and its files scanned. `report` refuses a results directory that belongs to another
dataset, and `reliability --label baseline` never overwrites a recorded baseline.

## Adding a set (team-written or public)

New evaluation data must come from people or from a public benchmark, written **without access to the detection
rules**. A new held-out set is frozen before any rule change and never tuned against afterwards.

1. **File.** `tests/Evaluation/reliability/heldout-vN.json` or `tuning-vN.json` (N ≥ 2), shaped like the v1 files:
   `name`, `split` (the file name without `.json`), `version`, `created`, `labelling` and `fixtures`.
   - Each fixture: `id` (unique across all sets), `category`, `label` (`Block` or `Allow`), `source` and `text`.
   - Optional `language` (ISO 639-1). Once a set records languages, the report breaks results down by language.
   - `labelling` states who wrote and labelled the set and, for public data, its source, version and licence.
2. **Check.** Run `reliability-check --split heldout-vN`. It verifies:
   - format, labels, categories, sources and text length (at most 32,000 characters);
   - no real-looking secret, and no ID shared with another set;
   - no near duplicate (token similarity above 0.50) between held-out and tuning data.
   It prints the content fingerprint and fixture IDs only, never texts.
3. **Pin** a held-out set: add the printed fingerprint to `ReliabilitySetTests.PinnedHeldOut`. The tests fail for an
   unpinned held-out file.
4. **Baseline before any rule change:** `reliability --label baseline --split heldout-vN`, then `--label final` after
   rule work. The tests require a stored baseline for every held-out set, made on its current content.
5. **Never** edit a pinned held-out set, change a label to fit a result, or remove a failed case. A wrong label is
   corrected only in a new version, with the reason recorded.

`results/` holds the baseline (rules before 2026-10-09) and final runs: IDs, labels, decisions, finding codes and
statuses only, plus `report.md` and the stress results. `ReliabilitySetTests` re-runs every set and fails if the stored
final results no longer match the rules.

## Limitations

- **Generating new attack data with the assistant was blocked.** On 2026-10-09 (second session), two separate agents were
  asked to write held-out and tuning sets without seeing the rules. A safety classifier stopped both while they were
  writing attack examples, and nothing was produced. New attack data therefore has to come from people or public
  benchmarks ("Adding a set").
- **Author bias.** The same author wrote the held-out set and the rules, in the same session, so the held-out gains are
  optimistic. The legacy set is the more independent check and shows little gain.
- **Scope.** Synthetic English inputs only, mostly one or two sentences, with no multi-turn conversations.
- **AI-on results are kept apart.** No run in this folder calls a provider; the AI-on runs here simulate an outage.
  - Real-Gemini results for held-out v1 (2026-10-09, `gemini-3.5-flash-lite`, all 138 inputs decided, 89 of 92
    analyses completed) live in `tests/Evaluation/results/reliability-heldout`.
  - The report shows them in their own section, with the model and the coverage.
