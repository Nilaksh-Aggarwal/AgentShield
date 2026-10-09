# Reliability sets

Labelled, synthetic inputs for measuring the **deterministic** firewall on Problem 2's textual attack types, with a
tuning/held-out split ([ADR 0025](../../../docs/decisions/0025-reliability-rules-and-held-out-evaluation.md)). Test data
only: nothing in `src/` reads it.

| File | Inputs | Role |
|---|---|---|
| `heldout-v1.json` | 138 (78 Block, 60 Allow) | Written **before any rule change** on 2026-10-09 (file SHA-256 `45ed95c0…0374`, recorded 02:31:33 UTC; content fingerprint `bb758c1a…5d11`, pinned by `ReliabilitySetTests`). Only measured; never edited. |
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
dotnet run --project tests/AgentShield.Evaluation -- reliability-stress --hosts 4 --concurrency 16 --rounds 3 --burn 8
dotnet run --project tests/AgentShield.Evaluation -- reliability-report
```

`results/` holds the baseline (rules before 2026-10-09) and final runs: IDs, labels, decisions, finding codes and
statuses only, plus `report.md` and the stress results. `ReliabilitySetTests` re-runs every set and fails if the stored
final results no longer match the rules.

## Limitations

- **Author bias.** The same author wrote the held-out set and the rules, in the same session, so the held-out gains are
  optimistic. The legacy set is the more independent check and shows little gain.
- **Scope.** Synthetic English inputs only, mostly one or two sentences, with no multi-turn conversations.
- **No AI accuracy here.** No result in this folder measures AI-assisted accuracy. The only AI-on runs simulate an
  outage, with no provider called.
