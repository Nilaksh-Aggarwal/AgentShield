# 0027 — Retiring held-out v1 to development data; tool-abuse rule and redactor retry

- **Status:** Accepted — 2026-10-09 (owner instruction).
- **Amends:** [0025](0025-reliability-rules-and-held-out-evaluation.md) and
  [0026](0026-versioned-held-out-sets-and-real-model-runs.md) for held-out v1 only. Every other held-out rule stands.

## Context

- **The evaluation:** held-out v1 (138 inputs) was evaluated deterministically and, on 2026-10-09, with real Gemini
  (`gemini-3.5-flash-lite`, all 138 inputs decided). Tool abuse was its weakest category: 6/10 with and without AI.
- **The owner's instruction:** investigate the four missed tool-abuse inputs. If that meant using the held-out set for
  debugging, it must be relabelled as development data and its original results preserved.
- **The rule this changes:** ADR 0025 and `CLAUDE.md` say a held-out split is never tuned against.
- **A second finding:** under CPU oversubscription the log and AI-disclosure redactor masked ordinary text, because
  its regex timeout is wall-clock time. With AI on, that withholds the input from the provider, so it is held for
  review.

## Decision

1. **Held-out v1 is retired to development data, effective 2026-10-09.**
   - Before any of its texts were studied, its results were frozen in
     `tests/Evaluation/reliability/results/frozen-heldout-v1`: the deterministic baseline and final, the simulated
     outage, and the report as it stood.
   - Those frozen files and the real-Gemini records in `tests/Evaluation/results/reliability-heldout` are its held-out
     evidence. `ReliabilitySetTests` pins their content.
   - The data file stays pinned and unedited.
   - Later measurements on it are development numbers, and the report says so (`ReliabilityDataset.Retired`).
2. **IO-006 (`ToolMisuse`, Medium → Review) gains two commands, each requiring an imperative:**
   - a destructive tool or function invoked by name against every row, record or table, or against production;
   - a security configuration file or policy blanked out.
   - Warnings, questions, runbooks with a limited scope, and ordinary empty values do not match (`ToolAbuseRuleTests`).
3. **No text rule for credential entry into a form (HO-TA-05).**
   - Password managers, sign-in help and password-reset e-mails describe the same action.
   - What makes it an attack is whether the destination is trustworthy, which the text firewall cannot know.
   - That belongs to tool-level policy (the gateway's argument policies), and it stays a stated gap.
4. **The redactor retries once.**
   - `SensitiveDataRedactor.TryRedactValue` runs the whole redaction once more from the original value after a timeout.
   - A second timeout masks the whole value, as before.
   - Timeouts and patterns are unchanged.

## Pre-commit review (2026-10-09)

An independent review of the uncommitted changes led to these corrections. No result in the frozen evidence changed.

- **IO-006 narrowed.** The first version flagged 11 realistic benign inputs and missed 8 hostile variants, all now in
  `ToolAbuseRuleTests`.
  - Benign inputs it flagged: "Do not, under any circumstances, run drop_database on production", "then use
    drop_duplicates on all rows", "replace the auth header with an empty string", "Replace William's signature with a
    blank line".
  - Hostile variants it missed: a quoted or `.py` tool name, "you must run …", "truncate /etc/sudoers", an empty JSON
    object.
  - What changed:
    - a command must open a line or sentence, or be an explicit order;
    - only tools named for a data store count;
    - only tool words may separate the tool from its target;
    - security terms must start a word and name a file or configuration, so bare "auth" and "policy" no longer count.
  - Remaining misses are recorded as such: camelCase names, verbs outside the list, and HO-TA-05.
  - Development-data result unchanged: tool abuse 9/10 on v1, no other decision changed. Tuning and legacy unchanged.
- **The resume never re-sends a fixture that was in flight.** A send record without an attempt is never planned again,
  with or without `--exclude-failed`.
- **Retired sets are development data in the tooling.**
  - They are refused for `plan`, `final`, `simulate` and `baseline`.
  - An active held-out set is checked for near duplicates against them as well as against tuning sets.
  - The retirement has a timestamp (06:20:35 UTC, after the last real session at 06:11:20 UTC), so the report states
    which real sessions predate it.
- **Recorded results are protected.**
  - A recorded baseline is never overwritten.
  - `report` refuses a results directory whose sessions or baseline belong to another dataset.
- **The stall tests cannot pass vacuously.** A control test shows that the same stall times out a bare match.

## Consequences

- **Measured on development data (not evidence):**
  - held-out v1 tool abuse goes from 6/10 to 9/10, with no other decision changed;
  - tuning v1 and the legacy set are unchanged, including their false positives.
- **The real-Gemini records predate the rule change.** The report flags that 3 deterministic decisions now differ.
  AI-on figures for the new rules were not measured.
- **A credible D2 claim needs a new held-out set** that is independently written or reviewed (ADR 0026, "Adding a set").
- **Redactor under the same oversubscription (8 cores, 48–96 burner threads, 20 s):**
  - before the change, 86 of 2,151,960 redactions of an ordinary sentence fell back to the mask;
  - after it, 0 of 2,113,548.
  - It still fails safe after two timeouts, and it never returns partially redacted or unredacted content.
