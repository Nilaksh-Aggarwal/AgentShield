# AgentShield — Submission Readiness

Local pre-publication audit, 2026-10-09 (Windows 11, .NET SDK 10.0.101, Node 22.23.2, npm 12.2.0).

**Scope.** The only available copy of the project was extracted from a ZIP archive of the original working folder. The
ZIP contains **no Git history**, so this audit covers files only. Every result below was verified **in this copy**.
Results recorded in `docs/PROGRESS.md` were verified in the original project and serve only as historical evidence. No
Git repository was initialised, nothing was committed, and nothing was published.

Statuses: **PASS** directly verified · **FAIL** verified problem · **PARTIAL** incomplete · **NOT VERIFIED** insufficient
evidence · **NOT APPLICABLE**.

## Submission deliverables

| Deliverable | Status | Evidence |
|---|---|---|
| Working prototype | **PASS** | Builds and passes every check from a clean copy of the commit set (below) |
| Public GitHub repository | **NOT VERIFIED — not created** | No Git repository or remote exists yet |
| Pitch deck (PDF or PowerPoint) | **NOT VERIFIED** | Updated in Canva (per the project owner, including the slide 9 fix); the final exported file or link has not been checked. Not in the repository |
| Demo video (2–4 min) | **NOT VERIFIED** | Not confirmed as recorded or uploaded |
| README, installation, dependencies, architecture, API docs, environment setup | **PASS** | Sections 3, 9–11 |
| License | **PASS** | MIT `LICENSE` prepared, Copyright (c) 2026 Nilaksh Aggarwal; the hackathon's IP terms rest on the owner's confirmation (section 13) |
| Official Phase 2 problem-statement wording | **NOT VERIFIED** | The original brief is not in the repository; the README states the problem as the project frames it and marks the official wording as requiring confirmation |

## 1. Correct project folder — PARTIAL

The original folder (with its Git history) is unavailable. The available copy, extracted from the ZIP, is the only
candidate. Its logs show it was run from the original folder on 2026-10-08, and its source matches the latest milestone
in `docs/PROGRESS.md` (Milestone 14). Whether the original folder held newer, unzipped changes cannot be verified.

## 2. Git repository and remote — NOT VERIFIED

There is no `.git` directory and no remote. A first commit from this copy will start a new history.

## 3. README — PASS

The README covers:

- Quick Start
- problem (marked as the project's framing) and solution, with a Mermaid data-flow diagram
- verified capabilities and what is not implemented
- architecture, and the technology stack with versions taken from the project files
- repository structure and prerequisites
- startup, configuration and the API
- the demo walkthrough, using the real Attack Lab scenario IDs
- testing and build commands, with results
- security, AI-assisted versus deterministic analysis, and known limitations
- license status

These claims were checked against the source on 2026-10-09:

- risk bands: Medium from 30, High from 70; the policy blocks at High
- Critical agent actions are always blocked
- approvals last 600 s by default; the list returns at most 50
- Gemini response cap 256 KiB
- execution grants: HMAC-SHA256, 30 s
- activity history capacity 1,000 events
- default model `gemini-3.8-flash`; timeout 1–3 s

## 4. `.gitignore` and first-commit contents — PASS

Verified with a temporary Git index **outside** the project (`git add -A --dry-run`, `git status --ignored`,
`git check-ignore`); the project folder was not turned into a repository.

**Included: 647 files** (1.8 MB): the 646 files verified in section 7, plus `LICENSE` (added afterwards).

| Area | Files | Contents |
|---|---|---|
| Root | 12 | `.editorconfig`, `.gitignore`, `AgentShield.slnx`, `CLAUDE.md`, `Directory.Build.props`, `Directory.Packages.props`, `LICENSE`, `README.md`, `SUBMISSION_READINESS.md`, `dotnet-tools.json`, `global.json`, `nuget.config` |
| `src/` | 209 | All six projects: `.cs`, `.csproj`, `appsettings.json`, `appsettings.Development.json`, `Properties/launchSettings.json`, `AgentShield.Api.http` |
| `tests/` | 211 | Five test/tool projects, the `Evaluation/` set and its metadata-only results, `mutation/` Stryker configurations |
| `frontend/agentshield-web` | 155 | `package.json`, `package-lock.json`, `.env.example`, `.gitignore`, TS/Vite/ESLint/Vitest configs, `index.html`, `public/favicon.svg`, `src/`, `e2e/` scripts and fixture |
| `docs/` | 47 | `API.md`, architecture, API conventions, security, 23 ADRs, evaluation write-ups, `PROGRESS.md` |
| `scripts/` | 2 | `new-api-key.ps1`, `gemini-smoke.ps1` |
| `artifacts/hackathon/screenshots` | 11 | 10 PNG files and their README |

**Excluded** (all generated or local):

- `.vs/`
- every project's `bin/` and `obj/`
- `src/AgentShield.Api/AgentShield.Api.csproj.user`
- `src/AgentShield.Api/logs/` (contains local machine paths)
- `frontend/agentshield-web/node_modules/`, `dist/` and `e2e/.results/`
- `tests/mutation/StrykerOutput/` (contains local machine paths)

**Nothing important is ignored.** Exactly these 646 files, copied into an empty folder, restored, built, tested and
passed the browser checks (section 7).

**Rules added in this preparation** (root `.gitignore`):

- OS files
- `.env.*`, with `!.env.example` keeping the frontend template
- `secrets.json`, `*.pfx`, `*.pem`
- `coverage/`

## 5. Secret and machine-information scan — PASS

Scanned all 636 non-image files in the commit set for:

- Google, AWS, GitHub, Slack and `sk-` style keys
- private-key blocks, Azure account keys and SAS tokens
- JWTs and `Password=` values
- private IP addresses
- personal paths, usernames and email addresses

Findings:

- **No real secrets.** Every key-shaped value is a deliberate, obviously fake test value in `tests/`:
  - "FakeKeyForAgentShieldTests"-style Google keys
  - AWS's documented example access key
  - all-alphabet GitHub and `sk-` placeholders
  - sample JWTs (for example the jwt.io "John Doe" token)
  - passwords such as `hunter2` and `not-a-real-secret`
- **Configuration:** `appsettings*.json` keep `Ai:Gemini:ApiKey` and `ConnectionStrings:AgentShield` empty. The only key
  hash is the documented public Development key's, accepted only in Development.
- **No personal paths, usernames or email addresses** in the commit set.
- **Screenshots:** the PNGs carry no text, EXIF or time metadata chunks. Two were inspected visually and show only the
  application with synthetic data and per-run IDs.
- **Not in the project:** the real Gemini key lives in .NET User Secrets on this machine, outside the project folder,
  and was not opened.

## 6. Git-history audit — NOT VERIFIED

There is no history in this copy. If the original repository was ever pushed or shared, its history must be scanned
separately.

## 7. Backend build and tests — PASS (new check, 2026-10-09)

Run in a fresh folder holding only the 646 commit-set files:

- `dotnet restore`: succeeded
- `dotnet build AgentShield.slnx`: 0 warnings, 0 errors

| Suite | Total | Passed | Failed | Skipped |
|---|---|---|---|---|
| UnitTests | 837 | 837 | 0 | 0 |
| SecurityTests | 1,082 | 1,082 | 0 | 0 |
| ApiTests | 565 | 565 | 0 | 0 |
| IntegrationTests | 264 | 264 | 0 | 0 |

Building inside the extracted folder itself is blocked by a Development API started from that folder (port 5102). It
locks `bin\` and caused 10 MSB3021/MSB3027 copy errors in a `--no-incremental` build on 2026-10-09; there were no
compiler errors. That API was not stopped. Mutation testing was not re-run.

## 8. Frontend lint, tests, build and browser checks — PASS (new check, 2026-10-09)

- `npm ci`: 243 packages, 0 vulnerabilities
- `npm run lint`: clean
- `npm test`: 387 passed in 21 files
- `npm run build`: succeeded
- `npm audit`: 0 vulnerabilities
- `npm run test:e2e`: **2,118 checks, 0 failed** (Analyze 836, Overview 479, Agents 379, Attack Lab 424). The 12 console
  entries are the Analyze suite's deliberate 401/403/429/502 runs.

**Historical intermittent result:** one browser-check run on 2026-10-08 failed 3 of 4 suites (headless Chrome stalls and
one missing button). Three later runs passed completely; the cause was not identified.

## 9. API documentation — PASS

`docs/API.md`: every controller route with its permission, rate-limit policy, request fields from the DTOs and
validators, and responses captured from a running Development API on 2026-10-08. Swagger UI and the OpenAPI document
answered 200 in Development.

## 10. Architecture documentation — PASS

README Architecture section and Mermaid diagram, `docs/architecture/overview.md`,
`docs/security/security-architecture.md`, and 23 ADRs.

## 11. Environment setup — PASS

The API reads ASP.NET Core configuration (appsettings, User Secrets, environment variables), not `.env` files, so no
backend `.env.example` exists. Every setting is in the README's Configuration table. The frontend `.env.example` holds
no secrets. The demo needs no database and no AI key.

## 12. Demo reproducibility — PASS

- **2026-10-08, live API (Development, AI off):** the Allow, Review and Block flows; tool gateway execution and
  rejection; approve-then-run-once; 409 and 400 contract errors; activity and its summary.
- **2026-10-09:** the browser checks drove the same flows through the console, from the clean copy.

## 13. License — PASS (file prepared; ownership confirmed by the project owner, not independently verifiable)

- **`LICENSE`:** standard MIT License, `Copyright (c) 2026 Nilaksh Aggarwal`. The body is byte-for-byte identical to
  the MIT text shipped with `react`, `react-dom` and `scheduler`; only the copyright line differs.
- **Copyright holder:** named by the project owner on 2026-10-09; the project itself named no author.
- **Checked in the repository:**
  - no prior license or copyright notice
  - no employer, team, co-author, contributor-agreement, proprietary or confidential marking on the project
  - no vendored third-party code
  - the favicon is the project's own SVG; the screenshots show only this application
- **Dependencies:** MIT, Apache-2.0 or PostgreSQL License, all compatible. They are restored at build time, not stored
  in the repository, and keep their own terms.
- **README License section:** states MIT with the same holder, scopes it to the repository's own content, says
  dependencies keep their licenses, and notes trademarks.
- **Not verifiable from here, and resting on the owner's confirmation:**
  - the hackathon's terms (ET AI Hackathon / Unstop) on intellectual property and licensing
  - any employment or academic agreement
  - whether anyone else contributed code

## 14. Public GitHub readiness — PARTIAL

The content is ready: it builds from a clean copy, contains no secrets or personal paths, is MIT-licensed, and its
documentation is consistent with the source. Still open: Git initialisation and first commit, and the GitHub
repository. The commit set is now **647 files**: the 646 verified on 2026-10-09 plus `LICENSE`. The files that changed
since that run (`README.md`, `SUBMISSION_READINESS.md`, `docs/PROGRESS.md`, `LICENSE`) are documentation only.

## 15. Pitch deck and demo video — NOT VERIFIED

Neither is in the repository or checkable from here. No links or placeholders were added to the README. Add the real
links once the deck is exported and the video is uploaded.

## 16. Public documents reviewed

| Document | Recommendation | Reason |
|---|---|---|
| `README.md` | Include | Current, verified against source |
| `docs/API.md` | Include | Verified routes and captured responses |
| `.gitignore` | Include | Verified include/exclude behaviour |
| `SUBMISSION_READINESS.md` | Include, or remove before the final commit | Accurate, but an internal checklist rather than project documentation |
| `CLAUDE.md` | Include | Accurate architectural and security constraints that match the code; no secrets or personal data. Written as instructions for AI coding sessions, which is worth knowing for judges |
| `docs/PROGRESS.md` | Include | Accurate, dated development log with verification evidence; no secrets, keys or paths. Long (about 2,300 lines), and early entries are superseded. A preface now says so and points to the README. Mentions the Gemini free-tier quota figures and that evaluations were run by the assistant; harmless, but internal in tone |

## 17. Remaining actions

1. **Pitch deck:** export the final Canva deck to PDF or PPTX and verify it, then link it from the README. Not verified.
2. **Demo video (2–4 min):** record and upload it, then link it from the README. Not verified.
3. **Official Phase 2 problem statement:** verify the exact title and wording against the hackathon brief. The README
   marks it as requiring confirmation.
4. **Licensing terms:** confirm the hackathon's IP and licensing rules allow MIT publication by the owner (section 13).
5. **Git:** initialisation, review of the staged files, the first commit and the GitHub repository (your approval
   required). The global Git identity on this machine will be used unless changed; its email becomes public in the
   commit history.
6. Optional: decide whether `SUBMISSION_READINESS.md` stays in the public repository.
7. The flaky browser-check run of 2026-10-08 is not root-caused.
