# AgentShield — Submission Readiness

Audit against **ET AI Hackathon: Agentic Edition — Detailed Problem Statements** (Problem 2, pages 6–8; framework and
final-submission expectations, pages 2–4), updated **2026-10-09** after the D2 × F2 reliability work. Environment:
Windows 11, .NET SDK 10.0.101, Node 22.23.2, npm 12.2.0.

Statuses: **PASS** verified · **PARTIAL** important cases missing · **FAIL** not implemented or fails · **NOT VERIFIED**
insufficient evidence · **NOT APPLICABLE**.

**Verdict on this work: IMPROVED BUT D2 NOT YET DEMONSTRATED.**
- Deterministic precision and the false-positive rate meet the internal D2 targets, but held-out recall (0.705) does not
  reach 0.90.
- The independent legacy set barely moved (0.415).
- AI-assisted accuracy on the new sets was not measured, because no live Gemini call was authorized.

## 1. Repository state

- **Git:** the local folder is a Git repository; `main` tracks `origin/main` (`https://github.com/Nilaksh-Aggarwal/AgentShield.git`).
  The only commit is `039fbc5 AgentShield: initial public submission`. Nothing in this work was committed or pushed.
- **FAIL — the published commit fails its own tests.** `039fbc5` contains the Attack Lab scenarios I-10/I-11 but pins
  the activity count at 15, while the scenarios produce 17. `dotnet test` therefore fails one ApiTests test on GitHub
  `main`, and the browser checks fail two. The fix was already in the uncommitted working tree before this work, and the
  current working tree passes everything (section 10).

## 2. Official Problem 2 requirements (pages 6–8)

- **Title and objective:** *Agentic Cybersecurity – Prompt Injection Firewall*: intercept all incoming content before it
  influences the AI's behavior, detect and neutralize malicious prompt injections, and let legitimate content pass with
  minimal disruption.
- **Inputs:** user messages, web pages, PDFs, emails, Markdown, HTML, Word documents, API responses, OCR text, source
  code, images via OCR.
- **Attacks:** instruction override, role change, secret extraction, tool abuse, credential theft, context poisoning,
  multi-step jailbreaks, encoded instructions, indirect prompt injection.
- **Depth:** D1 textual input with acceptable outputs in most situations; D2 textual input with a high degree of
  demonstrable reliability; D3 heterogeneous multimodal input with high reliability.
- **Features:** F1 ≥ 2, F2 ≥ 5, F3 ≥ 7 attack types detected.

## 3. Pipeline (traced in code, unchanged by this work)

`AnalyzeInputUseCase`:
1. Strict JSON and validation.
2. `InputNormalizer`.
3. Every detector (3 pattern detectors, now 22 rules, plus the obfuscation detector).
4. `FindingAggregator`.
5. `AiAssistedAnalysis` (skipped on a deterministic Block; disclosure, token estimate, circuit breaker, capacity, one
   Gemini call, strict validation).
6. `FindingAggregator` over all findings.
7. `SeverityRiskEngine`.
8. `RiskThresholdPolicyEngine`.
9. Security event to every sink (fail closed).
10. Response.

The agent path, tool gateway, approvals and audit are unchanged.

## 4. Nine-attack coverage matrix (AI off; held-out set, 138 inputs written before any rule change)

| Attack type | Implementation evidence | Tests | Demonstrated | Held-out before → after | Status | Gap |
|---|---|---|---|---|---|---|
| 1. Instruction Override | IO-001..IO-003; new IO-004 (revoked), IO-005 (abandon) | `InstructionOverrideDetectorTests`, `RetrievedContentEndpointTests`, reliability sets | I-01 | 2/10 → 5/10 | **PARTIAL** | Paraphrases; legacy paraphrased 0/6 |
| 2. Role Change | RM-001..RM-003; new RM-004 (privileged role), RM-005 (safety bypass) | `RoleManipulationDetectorTests`, Attack Lab tests | I-02, I-09 (now Block) | 0/8 → 3/8 | **PARTIAL** | Role play, indirect claims |
| 3. Secret Extraction | SE-001; new SE-003 (configuration disclosure) | `SecretExtractionDetectorTests` | I-01 | 2/8 → 6/8 | **PASS** for common phrasings | Indirect phrasings |
| 4. Tool Abuse | New IO-006..IO-010 (destructive, covert, approval bypass, bulk transfer, privilege escalation) plus gateway enforcement | `ToolGatewayEndpointTests`, reliability sets | T-02, T-03 | 0/10 → 6/10 | **PARTIAL** | Other wordings; one gateway-enforced tool |
| 5. Credential Theft | SE-002; new SE-004 (exfiltration), SE-005 (phishing) | `RetrievedContentEndpointTests`, reliability sets | I-03 | 0/10 → 8/10 | **PASS** for common phrasings | Indirect phishing |
| 6. Context Poisoning | RM-001/RM-003; new RM-006 (addressed to the AI, notices), RM-007 (false permission, memory) | `RetrievedContentEndpointTests`, reliability sets | I-11 | 2/10 → 8/10 | **PASS** for injected notices | False facts in plain prose |
| 7. Multi-Step Jailbreaks | None (no conversation state) | — | — | not in the set | **FAIL** | Needs conversation state |
| 8. Encoded Instructions | Obfuscation detector (all rules re-applied to decoded views) | `ObfuscationDetectorTests`, `ObfuscationEndpointTests` | I-04, I-05, I-08 | 10/10 → 10/10 | **PASS** | Short or split encodings |
| 9. Indirect Injection | The same rules on submitted retrieved text | `RetrievedContentEndpointTests` | I-10 | 4/12 → 9/12 | **PASS** for submitted text | No fetching, no tool-output screening |

Benign held-out inputs: **59/60 allowed** before and after. The one false positive (HB-SD-03, a security-training
request) predates this work.

## 5. Input-source matrix (unchanged)

| Source | Status |
|---|---|
| User messages, Markdown, HTML, emails, API responses, source code, OCR text | Supported as the text the application submits |
| Web pages | Only after the application fetches them |
| PDFs, Word documents, images (OCR) | **Not supported**: no extraction or OCR component exists |

## 6. Reliability evaluation (deterministic, AI off)

**Method** ([ADR 0025](docs/decisions/0025-reliability-rules-and-held-out-evaluation.md),
`tests/Evaluation/reliability/README.md`):
1. The held-out set (138) was written and fingerprinted at **02:31:33 UTC, before any rule change**.
2. A separate tuning set (95; maximum token overlap with held-out 0.43) was the only data the rules were developed
   against.
3. The baseline was recorded with the old rules, then the held-out set was measured **once** after rule development.
4. The earlier 113-input set (never tuned against) was measured the same way.

No label or held-out input was changed.

| Set | Baseline TP/FN/FP/TN | Final TP/FN/FP/TN | Recall | Precision | False-positive rate |
|---|---|---|---|---|---|
| Held-out (78 positive, 60 benign) | 20/58/1/59 | 55/23/1/59 | 0.256 → **0.705** (55/78) | 0.952 → **0.982** (55/56) | 1/60 → **1/60 (1.7%)** |
| Legacy (65 positive, 48 benign) | 25/40/4/44 | 27/38/4/44 | 0.385 → **0.415** (27/65) | 0.862 → 0.871 (27/31) | 4/48 → 4/48 (8.3%) |
| Tuning (59, 36) | 10/49/0/36 | 59/0/0/36 | developed against it: not evidence | | |

**Per category:**
- **Held-out** (section 4): encoded 10/10, credential theft 8/10, context poisoning 8/10, indirect 9/12, secret
  extraction 6/8, tool abuse 6/10, instruction override 5/10, role change 3/8.
- **Legacy:** paraphrased 0/6 → 0/6, non-English 0/9 → 0/9, multi-step 2/6 → 2/6, role/authority 4/6 → 5/6,
  system-prompt 2/6 → 3/6.

**Interpretation:**
- **The held-out figure is optimistic.** The same author wrote the held-out set and the rules in one session; the
  author's knowledge of the held-out wording cannot be excluded, even though it was frozen first.
- **Generalisation is weak.** The more independent legacy set shows the keyword rules generalise poorly.

**Internal D2 targets** (project engineering targets, not hackathon thresholds):

| Target | Result (held-out, AI off) | Met |
|---|---|---|
| Malicious recall ≥ 90% | 70.5% (55/78) | **No** |
| Precision ≥ 90% | 98.2% (55/56) | Yes |
| Benign false-positive rate ≤ 5% | 1.7% (1/60) | Yes |
| All security regression tests pass | 2,786 backend tests, 0 failed | Yes |
| Repeatable deterministic outcomes | identical results on repeated runs (`DeterministicRun_IsRepeatable`, stored-results test) | Yes |
| No unexplained 5xx within supported limits | 0 in the load runs below; one historical, unreproduced 500 (section 8) | Partly |

**AI-assisted results:**
- **No real Gemini call was made in this work** (not authorized). The only AI-on runs used a simulated outage (a fake
  transport returning HTTP 503, 0 network requests): every input the rules do not block → Review, 0 Allow, every
  deterministic Block kept (held-out: Allow 0, Review 92, Block 46).
- The earlier real-Gemini evaluation (2026-10-07, `gemini-3.5-flash-lite`, 81 completed analyses, legacy set, old rules)
  is historical and is not combined with these results.

## 7. Position in the 3 × 3 grid: **D1 × F2** (unchanged declaration)

- **Features:** 8 of 9 types now have implemented, tested detection (all but multi-step), with held-out detection between
  3/8 and 10/10. This work kept the declared tier at F2, as instructed. Whether this evidence supports F3 is the team's
  call; the hackathon penalises both over- and underestimation.
- **Depth:** D2 is not demonstrated: recall is below target, independent recall is 0.415, and AI-assisted accuracy is
  unmeasured. D3 needs multimodal input.

## 8. Reliability and performance

- **Load:** `reliability-stress` ran 4 in-process hosts × 16 concurrent requests × 3 rounds over 233 inputs (2,796
  analyses), twice.

  | Run | Non-200 | Server exceptions | Changed decisions | p50 / p95 / max |
  |---|---|---|---|---|
  | With 8 CPU-burning threads | 0 | 0 | 0 | 40.8 / 86.4 / 249.8 ms |
  | Without | 0 | 0 | 0 | 11.8 / 46.2 / 233.4 ms |

  The first attempt hit the Development rate limit (429s, 600 per minute per client). The stress hosts now raise the
  limit, as the API test hosts do.
- **Concurrency test:** `ConcurrentAnalysisTests` sends 192 simultaneous analyses, including maximum-length hostile
  inputs; every one returns 200 with the same result it gets alone.
- **Hostile inputs:** `Detect_MaximumLengthAdversarialInput_CompletesWithoutTimeout` gained 8 inputs built from the new
  rules' prefixes; all complete without a timeout.
- **The HTTP 500 of 2026-10-09:** **not reproduced** in 9 later full test runs (6 of them repeated specifically to
  reproduce it), 4 runs of the affected tests alone, or the load runs.
  - No log entry exists. A test host that cannot open the shared rolling log file writes no file log, so a missing entry
    is not evidence.
  - The cause is **unknown**. A regex timeout, which by design fails closed, is one possibility, not a finding.
  - Next step if it recurs: capture the exception with the in-memory log sink, as `reliability-stress` does.

## 9. Gemini configuration (Rule 2)

- **Effective default:** `Ai:Enabled = true` in `src/AgentShield.Api/appsettings.json` and `appsettings.Development.json`
  ([ADR 0024](docs/decisions/0024-ai-analysis-on-by-default.md)). The setting is `Ai:Enabled`; there is no
  `AiAnalysis:Enabled`.
- **Unchanged settings:** provider `Gemini`, model `gemini-3.8-flash`, timeout 3 s, capacity, circuit breaker.
- **Missing key:** the API refuses to start ("Gemini API key is missing"; `GeminiProviderPipelineTests`). Running without
  AI is explicit: `Ai__Enabled=false` or the new `http-deterministic` launch profile (pinned by
  `LaunchProfiles_KeepTheAiDefault_ExceptTheNamedDeterministicProfile`).
- **Boundary unchanged:** AI adds findings only; the deterministic risk and policy engines decide; AI never authorizes a
  tool action; every AI failure → Review.
- **Offline everywhere else:** tests, the browser checks and the evaluation runner force AI off or use fakes.
- **Consequences:**
  - **On this machine:** User Secrets hold a key, so the `http` profile now calls Gemini, sending content to Google
    (free tier, demo content only).
  - **Capacity:** each client gets 4 AI analyses a minute; more are held for review.
  - **Outages:** with the provider down, everything the rules do not block is held for review.
  - **Production:** it would need a key or an explicit off. No production secret or deployment was changed.

## 10. Verified results (2026-10-09, copy of the working tree)

| Check | Result |
|---|---|
| `dotnet build AgentShield.slnx` | 0 warnings, 0 errors |
| `dotnet test` | **2,786 passed, 0 failed, 0 skipped**: Unit 837, Security 1,090 (+8), Api 585 (+2), Integration 274 (+10) |
| `npm ci` / `npm run lint` / `npm test` / `npm run build` / `npm audit` | 0 vulnerabilities / clean / **402 passed** (+14) / built / 0 vulnerabilities |
| `npm run test:e2e` | **2,124 checks, 0 failed** (Analyze 836, Overview 479, Agents 379, Attack Lab 430) |
| Reliability runs | Section 6; no Gemini call; all results stored as IDs, codes and decisions |

Tests changed deliberately, with reasons:
- the AI validator's pinned detector-code count (11 → 25);
- the legacy deterministic Block count (26 → 28, so 87 → 85 AI-needed, 40 → 38 resumed);
- Attack Lab I-09 (Allow → Block) with the new I-12 known miss;
- the activity count (17 → 18);
- the committed `Ai:Enabled` value (false → true).

No security check was removed or weakened.

## 11. Submission deliverables

| Deliverable | Status |
|---|---|
| Working prototype | **PASS** (section 10) |
| Public GitHub repository | **PARTIAL**: published at `origin/main`, but that commit fails one test (section 1); the fixes are uncommitted |
| Pitch deck | **NOT VERIFIED**: in Canva; the export has not been checked. Its claims should match sections 4–9 |
| Demo video (2–4 min) | **NOT VERIFIED** |
| README, setup, API docs, architecture, environment | **PASS**; updated for AI on by default |
| License | **PASS**: MIT, Copyright (c) 2026 Nilaksh Aggarwal |
| Git-history secret scan | **PASS**: the history is one commit (`039fbc5`, 648 files); `git grep` found no key-shaped value outside `tests/` and none in the committed appsettings, and the keys in tests are the known fakes |

## 12. Remaining risks and next actions

1. **Commit and push the working tree after review** (needs your separate approvals). It fixes the failing published
   test and contains this work.
2. **Live Gemini evaluation** of the held-out set, if you authorize it with the AI Studio limits. Without it, AI-assisted
   reliability stays unmeasured and D2 cannot be claimed.
3. **Generalisation:**
   - an independently written (ideally human-written or reviewed) evaluation set;
   - paraphrase and non-English coverage, which is AI territory or needs a different technique than keyword rules.
4. **Not implemented:** multi-step jailbreak detection (conversation state); PDF, Word and OCR adapters; tool-output
   screening.
5. **The HTTP 500:** keep watching, and capture the exception if it recurs.
6. **Deck and video:** align them with the corrected claims: D1 × F2; I-09 now detected, I-12 the known miss; AI on by
   default; deterministic decisions.
