# 0026 — Versioned held-out sets and real-model runs of a held-out set

- **Status:** Accepted — 2026-10-09.
- **Extends:** [0017](0017-ai-evaluation-tooling-project.md) (AI evaluation runner) and
  [0025](0025-reliability-rules-and-held-out-evaluation.md) (reliability sets). Product code, rules, risk, policy and
  the API contract are unchanged.

## Context

After ADR 0025, three gaps blocked any further claim about reliability:

- **Held-out v1 has a known weakness.** It and the rules share an author, and its misses are published by ID.
- **A new set could not be added cleanly.** The tooling knew exactly one held-out and one tuning file, so a new set
  could not be frozen and pinned before rule work.
- **AI-assisted accuracy was unmeasured on the reliability sets.** The real-Gemini runner (ADR 0017) only ran the
  legacy 113-input set.

The first attempt to close the first gap was to have separate assistant instances write a new held-out and a new tuning
set without access to the rules. A safety classifier stopped both instances while they were writing attack examples,
and nothing was produced. That route was abandoned rather than worked around.

## Decision

1. **Versioned sets.**
   - `heldout-vN.json` and `tuning-vN.json` (N ≥ 2) sit next to the v1 files. The v1 splits keep their names
     (`heldout`, `tuning`) and fingerprints.
   - A fixture may record its `language`, which the report breaks results down by. It enters the fingerprint only when
     present.
2. **A set is checked, pinned and baselined before rule work.**
   - `reliability-check --split NAME` validates format, labels, categories, sources, text length, secret-like strings,
     IDs shared across sets, and near duplicates between held-out and tuning data. It prints IDs and fingerprints only.
   - `ReliabilitySetTests` fails for an unpinned held-out file and for a held-out set without a stored baseline made
     on its current content.
3. **New attack data comes from people or public benchmarks**, written without access to the rules. The file's
   `labelling` field records the author and labeller, and for public data the source, version and licence.
4. **Real Gemini on a held-out set goes through the existing runner and its safeguards.**
   - Run as `plan|final --dataset heldout…`; tuning sets and the legacy adaptation are refused.
   - Each set has its own results folder, `tests/Evaluation/results/reliability-<set>`. A real run refuses any other
     folder, so completed fixtures are never sent again.
   - The error probes use the legacy fixtures for the legacy set and fixed positions otherwise.
5. **Results stay apart.**
   - The reliability report keeps three kinds of result separate: deterministic, simulated outage, and real Gemini.
   - Its real-Gemini section reads only sessions recorded as `Real` and names the model.
   - It states coverage (fixtures with a final decision; completed AI analyses), and warns when the rules changed after
     the run.

## Addendum (2026-10-09): resuming a stopped held-out run

- **What happened.** The first real run stopped three times and left 48 inputs unsent:
  - a completed 2,642 ms call ended session 1;
  - the next two processes failed their first calls (a timeout; a 503, then a timeout).
- **The cause.** With a fake provider, the first AI analysis in a fresh process costs about 0.35–0.5 s of in-process
  start-up, against 1–3 ms later. That cost is spent inside the committed 3 s stage timeout.
- **Changes (evaluation only; production configuration, timeouts and controls unchanged):**
  - a write-ahead send record makes a mid-call crash visible, so such a fixture is never resent;
  - an opt-in warm-up runs one non-dataset text through a separate host with the local simulator (no network);
  - an opt-in flag stops ending sessions on *completed* slow calls; every failure stop is unchanged.
- **Why not a longer timeout:** the runner still refuses any timeout but the committed 3 s, so results keep
  describing the shipped configuration.

## Consequences

- No new held-out set exists yet. Held-out v1 remains the only pinned held-out set; its limitations (ADR 0025) stand.
- A real held-out run spends AI Studio quota and needs the owner's authorisation, with the day's limits stated on the
  command line.
- Detection rules are not changed by this decision. Rule work resumes only against tuning data, after a new held-out
  set has been pinned and baselined.
