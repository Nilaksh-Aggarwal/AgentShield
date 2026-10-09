# 0025 — Reliability rules and held-out evaluation

- **Status:** Accepted — 2026-10-09.
- **Extends:** [0010](0010-deterministic-firewall-pipeline.md) (deterministic pipeline) and
  [0011](0011-bounded-obfuscation-detection-and-finding-fusion.md) (bounded obfuscation detection). The pipeline, risk
  engine, policy, thresholds and API contract are unchanged.

## Context

Against Problem 2's attack types, the deterministic rules missed paraphrased overrides, credential exfiltration,
malicious tool-use instructions and context poisoning (`SUBMISSION_READINESS.md`). The only evaluation data, the 113-input
AI evaluation set, has no tuning/held-out split, so improving the rules against it would have destroyed it as evidence.

## Decision

1. **Measure before and after on data the rules were not developed against.** `tests/Evaluation/reliability` holds two
   synthetic, labelled splits:
   - `heldout-v1.json` (138 inputs) was written and fingerprinted **before any rule change** and is only measured;
     `ReliabilitySetTests` pins its fingerprint.
   - `tuning-v1.json` (95 inputs) is the only set the rules were developed against.
   - The splits share no input and no near-duplicate (token Jaccard ≤ 0.5, tested).
   - The legacy 113-input set is measured the same way and never tuned against.
   - The baseline and final runs, and a simulated provider outage, are stored as IDs, codes and decisions only. A
     test re-runs every set and requires the stored results to match, so the evidence cannot go stale.
2. **New rules in the existing detectors and categories.** There are no new categories and no contract change:
   - IO-004..IO-010: revoked or abandoned instructions; tool misuse (destructive or mass changes, covert actions,
     approval bypass, bulk data transfer, privilege escalation).
   - RM-004..RM-007: privileged role claims, safety bypass, context poisoning, false permissions.
   - SE-003..SE-005: configuration disclosure, credential exfiltration, credential phishing.
3. **The same constraints as every rule.** Rules are NonBacktracking with the 250 ms timeout, carry no input in
   findings, and are re-applied to decoded views. Rules that must not fire on questions or descriptions consume a clause
   start or a phrase end instead of using lookarounds. Overlaps with existing rules were removed, so a classic attack is
   still reported once.
4. **Severity follows intent and false-positive risk.** Explicit overrides, exfiltration and covert actions are High
   (Block). Destructive mass changes, privilege requests and content addressed to an AI are Medium (Review), because a
   person's legitimate request can share their wording.

## Consequences

- **Measured with AI off:**

  | Set | Recall | Precision | False-positive rate |
  |---|---|---|---|
  | Held-out | 0.256 → 0.705 (55/78) | 0.952 → 0.982 | 1/60 → 1/60 |
  | Legacy 113-input set | 0.385 → 0.415 (27/65) | 0.862 → 0.871 | 4/48 → 4/48 |

- **The held-out gain is optimistic.** The same author wrote the held-out set and the rules in one session. The legacy
  set, written earlier and independently, shows little gain: paraphrased 0/6 and non-English 0/9 before and after.
  Keyword rules do not generalise to unseen phrasing; the project's own D2 target (held-out recall ≥ 0.90) is not met
  deterministically.
- **Attack Lab I-09 is now detected.** "You are now the system administrator…" is caught by RM-004, so I-12 (an
  instruction in Spanish) became the labelled known miss.
- **Tests that pin counts changed.** Detector code count 11 → 25; legacy deterministic Blocks 26 → 28.
- **Under load, no errors and no drift.** 2 × 2,796 concurrent analyses on 4 hosts, one run with 8 CPU-burning threads:
  0 non-200 responses, 0 server exceptions, 0 changed decisions.
