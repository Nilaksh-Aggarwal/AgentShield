# Browser checks

The console checked in a real browser against the real API: the Analyze page (`analyze.check.mjs`); the Overview,
Activity, Not found pages and the shell (`overview.check.mjs`); and the agent authorization and tool gateway previews with
agent actions and tool calls on the Activity page (`agents.check.mjs`, Milestones 10 and 11); and the Attack Lab
(`attack-lab.check.mjs`, Milestone 12; human approval since Milestone 13). Current check counts are in docs/PROGRESS.md. They drive headless Chrome or Edge
through the Chrome DevTools Protocol with Node's built-in `fetch` and `WebSocket`: no test framework or browser download.

What they check, at 375, 768 and 1280 px in light and dark mode: page titles, one `h1`, landmarks, heading order, no
horizontal overflow, WCAG AA contrast of every visible text element, 44 px touch targets, keyboard paths and focus rings,
reduced motion, and no rule IDs, raw server text, percentages or invented metrics on screen. The Analyze checks run
real analyses (Allow, Review, Block, obfuscated and hidden-character attacks, unknown findings) and every failure the API
can produce: 401, 403, 422, 429 with `Retry-After`, 500 and an unreachable API. The Activity checks run after them
against the same API, so the history holds the Analyze suite's analyses: they check that it lists them (Block
included), filters and pages, opens a row to its trace IDs by mouse and keyboard, never shows any of the analysed texts,
hidden characters or AI failure reasons, and explains a wrong key (401), a missing `activity:read` permission (403) and
an unreachable API. The Agents checks run last: the preview is labelled as example data, shows no decision before it runs,
then sends its nine examples to the real authorization boundary (Development demo agents) and must show exactly the
decision, reason and risk each one gets; the Activity page then lists them as agent actions (recognised names only, no
AI status, no score); a wrong key (401), a missing `agent:authorize` permission (403) and an unreachable API are
explained without decisions or server text. The tool gateway preview (Milestone 11) shows no outcome before it runs, then
sends its eight tool calls to the real gateway as research-agent: the lookup runs and shows the dataset's text, the
lookup of an unknown topic runs and finds nothing, and the smuggled argument, the empty query, the high-risk action, the
capability it does not hold, the allowed action without a tool and the blocked input do not run and show no dataset text.
Activity lists them as tool calls without arguments or results; 401, a missing `tool:execute` permission (403) and an
unreachable API are explained without outcomes or server text. The approval panel (Milestone 13) reads the real store:
nothing is waiting at that point, and a wrong key, a client without `agent:approve` and an unreachable API each get their
own explanation and no list. The Attack Lab checks run last against the same API: the
brief's five workflows (prompt injection blocked with its finding and risk; a safe question allowed; the safe tool call
allowed and executed; the ungranted tool call blocked and not executed; the smuggled argument rejected and not
executed) and every other scenario must get exactly the decision the API tests pin, with no payload or internals in the
result; the replay is rejected before any decision; T-04 (Milestone 13) is held with a pending approval in the analysis's trace,
then approved (the lookup runs once, with its dataset text) and, run again, denied (nothing runs); a third hold appears on
the Agent security page's approval panel with its agent, tool, risk and reason and is denied there; on the rate-limited
instance, where approvals live 3 seconds, an approval decided too late is refused and its call never runs; the metadata-only export is captured in the page and checked; Activity
is searched by each run's correlation ID (the blocked input, the executed tool call, nothing for the rejected replay, and for T-04 its analysis and held call in one
trace, the approved run and the refused one)
and holds no payload even in closed rows; then layout at every width and scheme, keyboard, a wrong key, a missing
permission, an unreachable API, the firewall's rate limit with `Retry-After`, and reduced motion. The Overview suite
also checks the security operations counts (labels, real numbers, the honest scope label).

## Run

```bash
dotnet build AgentShield.slnx        # from the repository root: the API the checks start
cd frontend/agentshield-web
npm run build                        # the checks use the production build (vite preview)
npm run test:e2e
```

`e2e/run.mjs` starts two API instances from `src/AgentShield.Api/bin/Debug/net10.0` (Development; 5112 normal, 5113 with
a firewall limit of 3 per minute, a client without permissions and approvals that expire after 3 seconds), five `vite preview` servers (5174 normal, 5175 with a
wrong key, 5176 rate limited, 5177 without permission, 5178 pointing at the unused port 5199), and headless Chrome on
9333. It refuses to start if any of these ports is in use, and stops everything when it ends. It exits non-zero when a
check fails. Screenshots and `report.json` per suite go to `e2e/.results/` (ignored by Git). A run takes a few minutes.
On the way out it waits for the processes it killed to exit before removing their temporary directories (Windows keeps
a killed API's log file open until then, T-05); a directory it still cannot remove is reported as a warning and left in
the temp folder, never turned into a failed run.

- **No AI provider is contacted.** Both API instances run with `Ai__Enabled=false` and a blank `Ai__Gemini__ApiKey`,
  which override whatever User Secrets hold.
- Chrome or Edge is found in the usual install locations; set `CHROME_PATH` otherwise. `AGENTSHIELD_API_DLL` overrides
  the API build path.
- The keys used are the public Development key (added by the preview proxy) and two throwaway test keys; none is a secret.
