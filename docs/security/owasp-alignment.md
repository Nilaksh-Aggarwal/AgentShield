# OWASP alignment

How AgentShield's implemented controls relate to OWASP guidance, with the repository evidence for each and what is
missing. **This is an alignment map, not a compliance claim: AgentShield is not "OWASP compliant", and OWASP does not
certify compliance with these lists.** Status reflects the code and tests as of 2026-10-07 (Milestone 13).

References: [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/),
[LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) (mitigation strategies),
[LLM Prompt Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/LLM_Prompt_Injection_Prevention_Cheat_Sheet.html),
[OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/),
[OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
(ASI01–ASI10, section 4), [Agent Control Standard](https://genai.owasp.org/resource/agent-control-standard/) (section 5).

**Status**

| Status | Meaning |
|---|---|
| Implemented | A control exists and named automated tests prove it; limits are listed under Gap |
| Partially addressed | A control covers part of the concern; the Gap column says which part is missing |
| Not implemented | Relevant to AgentShield's purpose, but no control exists |
| Out of scope | Not applicable to what AgentShield is or does today |

**Two perspectives.** AgentShield is a control placed in front of someone else's agent (it screens input sent to that
agent). It is also an LLM application itself, because its optional AI stage sends content to Gemini. Rows say which
perspective they cover.

## 1. OWASP Top 10 for LLM Applications 2025

| OWASP concern | AgentShield control | Evidence | Gap |
|---|---|---|---|
| **LLM01 Prompt Injection** (protected agent) | **Partially addressed.** Deterministic detection of direct injection (instruction override, role manipulation, secret and system-prompt extraction), also when hidden by encoding (2 layers), character disguises or invisible Unicode; optional AI-assisted findings; deterministic risk and policy (Allow / Review / Block) | [Coverage matrix](security-coverage-matrix.md) sections 1–3 and 6; `InstructionOverrideDetectorTests`, `RoleManipulationDetectorTests`, `SecretExtractionDetectorTests`, `ObfuscationDetectorTests`, `HiddenCharacterDetectionTests`, `AnalyzeEndpointTests` | English keyword rules only: deterministic recall 0.38 (25/65) on the synthetic set, unreviewed labels. With AI off, non-English (0 of 10) and paraphrased (0 of 6) attacks are Allowed. No indirect, multi-turn or tool-output context. AI detection quality not established beyond the synthetic set (M14-R2: 81 of 87 real analyses, non-random coverage) |
| **LLM01 Prompt Injection** (AgentShield's own analyser) | **Implemented.** Content is sent as an untrusted JSON field, separate from the system instruction; the answer is schema-constrained, strictly parsed and validated all or nothing; it has no decision field and can only add findings from a closed catalogue | `GeminiRequestTests.SystemInstruction_NamesEveryCatalogueCode_AndTreatsTheContentAsUntrustedData`, `AiStructuredOutputParserTests`, `AiResponseValidatorTests`, `EveryFixture_SilentAi_ChangesNoDecisionAndNoFinding_…`, `Pipeline_WhateverTheAiAnswers_NoDeterministicFindingIsRemovedOrLowered_AndTheDecisionNeverDrops` | A manipulated model can still suppress its **own** findings (a "no findings" answer). Deterministic findings and their decision stand, Allow included (ai-analysis.md, section 14) |
| **LLM02 Sensitive Information Disclosure** | **Partially addressed.** Requests for credentials and the system prompt are detected in input. AgentShield itself never returns or logs the analysed input, decoded content or model text. Secrets, including Google API keys, are masked before content is sent to Gemini. Log properties and unhandled exception text are redacted; request paths and provider exception messages never reach a log; the Gemini API key lives only in User Secrets or the environment and goes only to the pinned endpoint | `SecretExtractionDetectorTests`; `Response_NeverEchoesTheInput`, `NoLogEntry_ContainsTheAnalysedInput`, `LogsAndResponse_NeverContainTheInputOrTheProviderAnswer`; `RedactingAiDisclosurePolicyTests`; `SensitiveDataRedactorTests`; `CommittedAppsettings_HoldOnlyAnEmptyKeyPlaceholder`; `UnhandledException_IsLoggedWithTypeMessageAndStack_ButSecretsInItsTextAreMasked`; `CallerControlledPathAndQuery_NeverReachTheLogs_OnlyTheRouteTemplateDoes` | The protected agent's **output** is not inspected, so a leak in an answer is not caught. No PII detection or masking before disclosure to Gemini (free tier: demo content only). The text of an unexpected exception is logged with secrets masked, but is not proven free of input fragments |
| **LLM03 Supply Chain** | **Partially addressed.** Central package versions; NuGet restores only from nuget.org; NuGet audit covers direct and transitive packages and its warnings must be triaged; the official Google.GenAI SDK; packages justified in dependencies.md; npm install reports 0 vulnerabilities | `Directory.Packages.props`, `nuget.config`, `Directory.Build.props` (`NuGetAudit`, `NuGetAuditMode=all`), [dependencies.md](../architecture/dependencies.md) | No SBOM, no package signature policy, no CI dependency scanning (CI/CD out of scope for this prototype). The model's provenance is Google's; the model name is configuration |
| **LLM04 Data and Model Poisoning** | **Out of scope.** AgentShield trains, fine-tunes and retrieves nothing | — | Poisoned documents reaching the protected agent are only screened if their text is submitted to `/analyze`; there is no document or source awareness |
| **LLM05 Improper Output Handling** (AgentShield's own model output) | **Implemented.** Model output is untrusted: size-capped (256 KiB response, 32 KiB answer), strictly parsed, codes from `AiFindingCatalog` only, model-written text never reaches a finding, response or log. A response the SDK cannot read is treated as malformed (D-15). The frontend renders API values as text (no `innerHTML`) with own-property lookups (D-17) | `AiStructuredOutputParserTests`, `AiResponseValidatorTests`, `GeminiSecurityAnalyzerTests` (response cap, `AnalyzeAsync_ResponseTheSdkCannotRead_IsMalformed_AndNothingOfItIsLogged`), `GeminiProviderPipelineTests` | — |
| **LLM05 Improper Output Handling** (protected agent's output) | **Not implemented.** The agent's answers are never inspected | Coverage matrix, "Not covered" | Output filtering is a future capability |
| **LLM06 Excessive Agency** (protected agent) | **Partially addressed (Milestones 10–11).** An agent action authorization boundary decides Allow / Review / Block per proposed tool action: configured agents bound to their runtime, one required capability per tool action, risk from declared effects, High → Review, Critical → Block, unknown → Block. A tool gateway enforces it for the one reference tool: the agent is its credential, arguments are checked, and the tool runs only for a signed, single-use grant issued on Allow | [agent-action-authorization.md](agent-action-authorization.md), [tool-gateway.md](tool-gateway.md); `AgentAttackScenarioTests`, `AgentActionPolicyTests`, `AgentActionAuthorizeEndpointTests`, `ToolGatewayEndpointTests`, `ExecutionGrantAuthorityTests` (invariants 44–70) | Enforced for `knowledge.lookup` only; every other tool is decided, not enforced, so a runtime that does not ask or ignores the answer is not controlled. Arguments of other tools and all tool results are not checked |
| **LLM06 Excessive Agency** (AgentShield's own model) | **Implemented.** The analyser has no tools, no grounding and no decision authority; the deterministic policy decides | `GeminiRequestTests.ResponseSchema_HasNoDecisionField_AndForbidsAdditionalProperties`, `AiResponseValidatorTests`; `GeminiRequest.Config()` sets no tools or grounding ([ADR 0012](../decisions/0012-ai-analysis-boundary.md), [ADR 0013](../decisions/0013-gemini-provider.md)) | No test asserts the absence of tools; it rests on the request code |
| **LLM07 System Prompt Leakage** | **Partially addressed.** System-prompt extraction requests are detected in input (High → Block). The analyser's own instruction cannot leak through AgentShield, because model text is never returned | `Detect_SystemPromptDisclosure_ReportsHighFinding`; `Findings_ExposeOnlyTheDocumentedClientFields` | Indirect phrasings are missed; the agent's output is not checked for a leaked prompt |
| **LLM08 Vector and Embedding Weaknesses** | **Out of scope.** No RAG, embeddings or vector store | — | — |
| **LLM09 Misinformation** (overreliance on model output) | **Partially addressed.** The LLM is never the security authority: AI findings pass through the deterministic risk engine and policy; confidence is informational and labelled heuristic in the UI; AI failures hold input for review | `Pipeline_AiConfidence_IsInformationalAndDoesNotChangeTheScore`, `AiFailurePolicyTests`, [ADR 0012](../decisions/0012-ai-analysis-boundary.md), [ADR 0016](../decisions/0016-ai-provider-circuit-breaker-and-input-token-budget.md) | AI-only findings have no severity ceiling, so a wrong answer can block a benign input (open policy decision since Milestone 3). The truthfulness of the agent's answers is out of scope |
| **LLM10 Unbounded Consumption** | **Implemented.** 1 MiB body, 32,000-character input, JSON depth 32, per-client rate limits, linear-time regexes with timeouts, bounded decoding, AI stage timeout (≤ 3 s), one provider attempt, per-client AI capacity budgets, token budget, circuit breaker, response caps | [principles.md](principles.md) section 4; `RequestSizeLimitTests`, `RateLimitingTests`, `DetectorContractTests`, `ObfuscationBoundsTests`, `InMemoryAiCapacityGateTests`, `AiInputTokenBudgetTests`, `InMemoryAiCircuitBreakerTests`, `AiCircuitBreakerPipelineTests` | All limits are per process (no distributed state). Unauthenticated requests are rejected but not rate limited. No long-term quotas |

## 2. LLM01:2025 mitigation strategies

OWASP lists seven mitigations. The cheat sheet adds that no single defense is sufficient, and that a guardrail LLM can
itself be injected. AgentShield is one layer: it screens input and never replaces controls inside the agent.

| OWASP concern | AgentShield control | Evidence | Gap |
|---|---|---|---|
| Constrain model behavior | **Partially addressed.** AgentShield's own analyser gets a fixed role, content marked as untrusted data, and a closed task | `GeminiRequest.SystemInstruction`, `GeminiRequestTests` | AgentShield cannot constrain the protected agent's prompt; the analyser's instruction is not evaluated for robustness (81 synthetic analyses, M14-R2) |
| Define and validate expected output formats | **Implemented** for AgentShield's own model output (JSON schema, strict parser, all-or-nothing validator) | `AiStructuredOutputParserTests`, `AiResponseValidatorTests` | Not applied to the agent's output |
| Input and output filtering | **Partially addressed.** Input filtering, including semantic analysis when AI is on, is implemented; output filtering is not | Coverage matrix sections 1–3 | Detection breadth (recall 0.38); no output filtering |
| Privilege control and least privilege | **Partially addressed.** AgentShield's own API: authenticated clients, named permission policies, per-client limits; its analyser has no tools | `AuthenticationTests`, `AuthorizationTests` (endpoint inventory), `RateLimitingTests` | No control over the agent's privileges or tools |
| Human approval for high-risk actions | **Partially addressed.** Review holds an input for a human (medium risk, uninspectable content, every AI failure); since Milestone 10 a High-risk agent action (external communication, sensitive data, privileged operation) is decided Review, and a Critical one Block | `MediumRiskInput_Returns200WithReview`, `ContentTooLargeToInspect_IsHeldForReview_NeverAllowedAndNeverTruncated`, `AiFailurePolicyTests`, `AgentAttackScenarioTests.Scenario3_HighImpactAction_WithTheCapability_IsHeldForHumanReview` | Since Milestone 13 a held tool call can be approved or denied by a person (`agent:approve`, a separate client outside Development) and then runs once, for the reference tool only; there is no review queue for held **inputs** (the caller acts on an input Review), no routing, roles or notifications, and no high-risk tool with a real executor to approve |
| Segregate and identify external content | **Partially addressed.** Inside the analyser request, untrusted content is kept apart from the instruction | `GeminiRequest.UserTurnJson`, `GeminiRequestTests.SystemInstruction_NamesEveryCatalogueCode_AndTreatsTheContentAsUntrustedData` | Requests carry no source, turn or tool context, so external content cannot be identified or treated differently |
| Adversarial testing and attack simulations | **Partially addressed.** The Attack Lab (Milestone 12) runs 14 fixed attack simulations against the live API from the console, each pinned by a backend test ([attack-lab.md](attack-lab.md)). Adversarial suites for every detector, obfuscation, hidden characters, 32,000-character hostile inputs and adversarial AI answers run on every test run; synthetic evaluation set with a deterministic baseline | `DetectorContractTests`, `ObfuscationBoundsTests`, `HiddenCharacterDetectionTests`, `AiResponseValidatorTests`, [test coverage summary](test-coverage-summary.md), `tests/Evaluation/results/report.md` | Evaluation labels are not yet reviewed by a person; real-model evaluation covers one model on a synthetic set (M14-R2: 81 of 87 analyses); no independent red team |

## 3. OWASP API Security Top 10 2023 (AgentShield's own API)

| OWASP concern | AgentShield control | Evidence | Gap |
|---|---|---|---|
| API1 Broken Object Level Authorization | **Out of scope.** No stored objects or object IDs are exposed (one analysis endpoint, no persistence) | — | Applies once security events become queryable |
| API2 Broken Authentication | **Implemented.** API keys stored as SHA-256 hashes, constant-time comparison, one identical 401 for every failure, key never logged; the public Development key is refused at startup outside Development | `AuthenticationTests`, `ProductionAuthenticationTests`, `SecurityConfigurationTests`, `AccessControlLoggingTests` | No identity provider for browser users; failed attempts are not rate limited (the key length makes guessing impractical) |
| API3 Broken Object Property Level Authorization | **Implemented.** Strict JSON input (unknown, duplicate and differently cased members → 400); responses expose only documented fields; rule IDs, detectors and decoded content are never returned | `JsonInputPolicyTests`, `Findings_ExposeOnlyTheDocumentedClientFields`, `Response_NeverRevealsRuleIdsDetectorsOrDecodedContent` | — |
| API4 Unrestricted Resource Consumption | **Implemented** | See LLM10 above | Per-process limits only |
| API5 Broken Function Level Authorization | **Implemented.** Fallback policy requires authentication everywhere; separate `firewall:analyze`, `activity:read`, `agent:authorize` and `tool:execute` permissions; only the health probes are anonymous (endpoint inventory tests) | `AuthorizationTests.EndpointInventory_OnlyTheHealthProbesAreAnonymous_AndAnalyzeAndActivityRequireTheirPermissionPolicies`, `AgentActionAuthorizeEndpointTests.EndpointInventory_TheAuthorizeEndpoint_RequiresExactlyTheAgentAuthorizePolicy`, `ToolGatewayEndpointTests.EndpointInventory_TheGatewayIsTheOnlyEndpointThatCanExecute_AndRequiresExactlyToolExecute` | — |
| API6 Unrestricted Access to Sensitive Business Flows | **Out of scope.** No business flow beyond analysis, which is rate limited | — | — |
| API7 Server Side Request Forgery | **Implemented.** The only outbound call goes to a pinned Gemini endpoint; no caller-supplied URL is ever fetched; redirects are not followed, so the key and content never go to another host | `GeminiSecurityAnalyzerTests.AnalyzeAsync_SendsOnePostToThePinnedGenerateContentEndpoint_WithTheKeyInAHeaderOnly`, `AnalyzeAsync_BaseUrlEnvironmentVariable_CannotRedirectTheRequestOrTheKey`; `GeminiRedirectTests.GeminiHttpClient_DoesNotFollowRedirects_SoTheKeyHeaderNeverReachesAnotherHost` | — |
| API8 Security Misconfiguration | **Implemented.** Options validated at startup; security headers; CORS allow-list (no wildcard, no credentials); Swagger off outside Development; Problem Details without internals; rate limiting cannot be disabled, and security events cannot be hidden by the log level, outside Development | `CompositionTests`, `SecurityHeadersTests`, `CorsTests`, `SwaggerTests`, `ErrorResponseContractTests`, `SwaggerTests.Swagger_IsDisabledOutsideDevelopment_ByDefault`, `SecurityConfigurationTests.SecurityEventsHiddenByTheLogLevel_OutsideDevelopment_FailsAtStartup` | Referrer-Policy and Permissions-Policy are not set; no reverse-proxy (forwarded headers) configuration |
| API9 Improper Inventory Management | **Partially addressed.** Versioned routes (`/api/v1`), an OpenAPI document, and a test that pins which endpoints are anonymous | `SwaggerTests`, `FirewallSwaggerTests`, endpoint inventory test | No deployment inventory (deployment out of scope) |
| API10 Unsafe Consumption of APIs | **Implemented.** Gemini responses are untrusted: capped, strictly parsed, validated; provider exception messages are never used or logged (an unmapped exception leaves without its message); redirects are not followed; one attempt, no retries | `GeminiSecurityAnalyzerTests`, `GeminiProviderPipelineTests`, `GeminiRedirectTests`, `AiStructuredOutputParserTests` | — |

## 4. OWASP Top 10 for Agentic Applications 2026

The 2026 list (OWASP GenAI Security Project, December 2025) describes risks of autonomous agents that plan and act with
tools. AgentShield is not an agent runtime: it screens input (Milestones 1–9), since Milestone 10 decides whether a
proposed agent action may run, and since Milestone 11 executes one reference tool through a tool gateway, only on Allow.
"Enforced" below applies to that tool only; for every other tool a decision is still only a decision.

### Focus risks

| OWASP risk | Built now | Evidence | Next (not built) |
|---|---|---|---|
| **ASI01 Agent Goal Hijack** | **Partially addressed.** Direct prompt injection in submitted input is detected (instruction override, role manipulation, secret extraction, obfuscated and hidden variants) and decided Allow / Review / Block. A hijacked agent's actions meet the authorization boundary: the input's Block or Review, when the runtime reports it, carries over to every action (it can only tighten); High-risk actions are Review and Critical ones Block whatever the agent's reasoning, which has no field in the request | [Coverage matrix](security-coverage-matrix.md); invariants 49, 50, 52; `AgentAttackScenarioTests.Scenario7_PolicyIntegrity_*` | Indirect injection (tool output, fetched pages, documents), multi-turn and memory context; detection breadth (deterministic recall 0.38 on the synthetic set). Since Milestone 13 a gateway call can reference its input's analysis (`inputEventId`) and is then decided on the server's record, not the runtime's report (invariant 78); the reference is optional, so a runtime that omits it is decided on the action alone |
| **ASI02 Tool Misuse and Exploitation** | **Partially addressed.** Per-action authorization: a catalogued tool action, exactly its required capability held by a configured agent, risk from declared effects, ordered deterministic policy; unknown tools and actions are blocked; capabilities are exact names (no wildcards); every decision is audited. **Enforced for the reference tool** (Milestone 11): complete mediation through the tool gateway (only its execution authority holds the tool), a per-tool argument policy, and execution only for a signed, single-use, call-bound grant issued on Allow; every stage audited before the next. Since Milestone 13 a Review runs only after a person approves exactly that call, once (invariants 74–76) | [agent-action-authorization.md](agent-action-authorization.md), [tool-gateway.md](tool-gateway.md); invariants 44–48, 52, 57–66; `AgentActionPolicyTests` (1,024 combinations), `ActionRiskClassifierTests` (2,047), `ReferenceToolCatalogTests`, `ToolGatewayEndpointTests`, `ToolGatewayRiskModelTests`, `ExecutionGrantAuthorityTests` | Enforcement for real tools (one in-memory reference tool only) and an MCP proxy; argument policies for other tools (recipients, amounts, paths, domains); tool-output screening; per-agent rate limits; a catalogue fed by tool registration |
| **ASI03 Identity and Privilege Abuse** | **Partially addressed.** Agents and grants come only from configuration and cannot change at runtime; an agent cannot grant itself a capability (no field, strict JSON); privilege-changing, credential and financial actions are Critical and denied to every agent; each agent is bound to the API clients allowed to act for it, and the caller comes from authentication; API permissions are separate (`firewall:analyze`, `activity:read`, `agent:authorize`, `tool:execute`, and since Milestone 13 `agent:approve`, which outside Development no agent credential may hold: an agent cannot approve its own calls). At the tool gateway the agent is its credential (one key, one agent), and every execution needs a short-lived, scoped, single-use grant the agent never sees | Invariants 45, 53, 55, 56, 61, 63–67; `AgentActionAuthorizerTests.Authorize_ACallerActingForAnAgentItIsNotBoundTo_IsBlocked`, `Authorize_TheClaimedCapabilityGrantsNothing_OnlyTheProfileDoes`, `ToolGatewayEndpointTests.Execute_TheAgentIsTheCredentials_TheSameBodyDecidesPerKey`, `ExecutionGrantAuthorityTests` | At `/agent/actions/authorize` a runtime still asserts the agent ID within its bound agents; API keys, not workload identity; just-in-time elevation with an approval workflow; per-user delegation |

### Other risks

| OWASP risk | Status | Note |
|---|---|---|
| ASI04 Agentic Supply Chain Vulnerabilities | Partially addressed for AgentShield itself (LLM03 row above) | No third-party tools, plugins or MCP servers are loaded |
| ASI05 Unexpected Code Execution | Not implemented | No code-execution tool is catalogued; a `shell` tool is unknown and therefore blocked (also at the gateway), but nothing inspects code. The one executable tool runs no code from its arguments |
| ASI06 Memory and Context Poisoning | Not implemented | No memory or context store is inspected (NEXT) |
| ASI07 Insecure Inter-Agent Communication | Not implemented | No inter-agent controls (NEXT) |
| ASI08 Cascading Failures | Partially addressed | Fail-closed decisions (500 with no decision, never an Allow), bounded AI usage and a circuit breaker; no cross-agent containment |
| ASI09 Human-Agent Trust Exploitation | Partially addressed | The console never presents an unknown decision or status as safe and labels the agent preview as example data. Since Milestone 13 a person approves or denies a held tool call from facts the server holds (agent from the key, tool, action, risk, reason, times), not from the agent's description; the approval binds the exact call, so a person cannot be talked into approving one call and have another run; the decision is recorded before it takes effect. Not addressed: what the approver is shown is metadata only (no argument preview), so a person approves a call they cannot fully see; no approver training, quorum or rate limit per approver |
| ASI10 Rogue Agents | Partially addressed | A rogue agent's actions are still decided by the boundary (unknown → Block, Critical → Block, grants fixed); nothing detects rogue behaviour over time, and a runtime that stops asking is not seen |

### Built now / next

| Built now | Next |
|---|---|
| Input security: deterministic detection, obfuscation and hidden-text handling, optional AI findings | Enforcement for real tools; an MCP proxy |
| Risk and policy engine (Allow / Review / Block), fail closed | MCP and other tool integrations |
| Agent action authorization foundation: configured agents bound to callers, capability checks per tool action, effect-based risk, deterministic policy | Indirect prompt injection and tool-output screening |
| Allow / Review / Block for agent actions; unknown → Block; Critical → Block | Argument-level policy for real tools; out-of-process execution grants |
| Tool gateway (M11): complete mediation, agent from its credential, argument policy, signed single-use execution grants, one reference tool | A mandatory input reference per agent |
| Human approval for held tool calls and input event binding (M13): Review runs only after a person approves exactly that call, once; the server's record of the input beats the agent's claim | Approval routing, approver roles and quorum, argument preview for the approver, durable approvals, a high-risk tool with a real executor |
| Audit log and metadata-only activity history for both kinds of decision | Memory and context protection; inter-agent controls |
| Attack Lab (M12): 14 deterministic scenarios run against the live API, metadata-only export; counts-only security operations summary | AI-assisted scenarios (after a real-model evaluation); scheduled or automated attack runs; durable audit storage |

## 5. Attack Lab demonstration (Milestone 12)

The Attack Lab ([attack-lab.md](attack-lab.md)) shows the controls above working on concrete attacks, against the real
API, with AI off. It demonstrates; it adds no control. Each row is **partial**: no scenario set demonstrates full
mitigation of any of these risks.

Current OWASP guidance for agent tools centres on **minimising extensions** (only the tools an agent needs),
**minimising extension functionality** (only the operations it needs), **minimising permissions**, **human approval for
high-impact actions**, and **complete mediation** in downstream systems (every call checked where it is executed). The
Attack Lab maps onto those concepts as follows.

| Risk | Built now: what the scenarios demonstrate | Concept | Next (not built) |
|---|---|---|---|
| **ASI01 Agent Goal Hijack** | I-01 to I-05: direct injection, a persona takeover, credential extraction, a Base64-encoded and a tag-character-hidden injection are blocked before they reach an agent; I-08: content too large to inspect is held for review; I-09 (known miss): a paraphrase is allowed, shown as a limitation | Input screening; fail-safe on what cannot be inspected | Indirect and multi-turn injection, detection beyond English keyword rules; T-04 shows a call decided on the server's record of its input (Review) despite the agent claiming Allow, but the reference is opt-in |
| **ASI02 Tool Misuse and Exploitation** | T-01: an authorised lookup runs once through a single-use grant; T-02: an argument outside the tool's schema is rejected and the tool never sees it; T-04: a call held for review runs only after a person approves it, once; denied or expired, it never runs | Complete mediation (for the reference tool); minimised extension functionality (an exact argument schema); human approval before a held call runs | Real tools behind the gateway and argument policies for them (so a high-risk action can be approved, not just held); tool-output screening; MCP |
| **ASI03 Identity and Privilege Abuse** | T-03: a capability the agent was never granted is blocked; T-05: presenting an execution ID as authorization is rejected before any decision (the agent never holds an execution credential); I-03: requests for credentials are blocked; the agent is its API key at the gateway | Minimised permissions (configured, exact capabilities); no standing execution credential in the agent | Workload identity instead of API keys; just-in-time elevation; per-user delegation; at `/agent/actions/authorize` a runtime still chooses among its bound agents |

**Minimising extensions** is shown only indirectly: research-agent holds four capabilities and one tool is executable;
anything not catalogued or not granted is blocked. **Complete mediation** holds for `knowledge.lookup` only: every other
tool is authorization-only, decided by AgentShield and executed (or not) by the application.

**Agent Control Standard.** The OWASP GenAI Security Project's
[Agent Control Standard](https://genai.owasp.org/resource/agent-control-standard/) focuses on agents that are
inspectable, traceable and instrumentable, with policy enforced at runtime. AgentShield does not implement it. It
relates partially: agents, capabilities and tool actions are declared in validated configuration and a code catalogue
(inspectable, without an agent bill of materials); every decision carries a security event ID and a correlation ID, and
every gateway stage is audited before the next (traceable); the tool gateway is a runtime policy enforcement point
(instrumentable) for one reference tool, without the standard's framework hooks.

| Built now | Next |
|---|---|
| Attack Lab: 14 deterministic scenarios against the live API (inputs, tool calls, a replay attempt, a known miss), each shown as the API answered | Real tools behind the gateway; MCP proxy |
| Security operations: counts of this process's in-memory history; Activity distinguishes inputs, agent actions and tool calls | Durable audit storage |
| Human approval of held tool calls (M13), in the Attack Lab (T-04) and on the Agent security page | Approval routing and roles; durable approvals |
| Metadata-only security report (export) | AI-assisted scenarios, once a real-model evaluation supports them |

## 6. Security closure (Milestone 13)

What Milestone 13 changed in the focus risks, built now against next. Each row is **partial**; none is a complete
mitigation.

| Risk | Built now | Next (not built) |
|---|---|---|
| **ASI01 Agent Goal Hijack** | A hijacked agent that acts on an input the firewall blocked or held cannot launder it through a claim: when the call references the analysis, the server's decision counts and the claim can only tighten (invariant 78) | Making the reference mandatory per agent; linking tool **output** back to the call that produced it (indirect injection) |
| **ASI02 Tool Misuse and Exploitation** | Review is no dead end and no loophole: a held call runs only after a person approves exactly that call (agent, tool, action, capability, arguments, input), once, before it expires; a Block is never lifted (invariants 74–76) | A real high-risk tool behind the gateway, so approval guards real effects; argument preview for the approver |
| **ASI03 Identity and Privilege Abuse** | Approving is its own permission and, outside Development, never held by an agent's credential (invariant 77); the approver is the authenticated client; the agent never holds an approval it could forge (IDs are the server's, the status is the server's) | Approver identity beyond an API key (named people, SSO); quorum for Critical-adjacent actions |
| **Human-agent trust (ASI09)** | The approver sees what the server knows, not what the agent says; every status shown is the API's; denied and expired say "Tool not executed" | Argument preview with redaction; approver training and fatigue controls |

**Agent Control Standard.** Milestone 13 adds to the "traceable" and "runtime-enforced" parts only: a person's decision
is an audit event tied to the held request's security event, and the approval is enforced at the same runtime point as
the grant. AgentShield still does not implement the standard (no hooks, no agent bill of materials, no framework
integration).

## What this map does not claim

- It is not a compliance statement and was not produced by an external assessment.
- The Attack Lab is a demonstration of implemented controls with 14 synthetic scenarios, not a benchmark or a
  penetration test; it claims no detection rate.
- "Implemented" means that tests prove the listed control, not that the concern is solved. Prompt injection in
  particular has no complete defense (OWASP LLM01:2025).
- Agent action authorization is a decision point; the tool gateway makes it an enforcement point only for the tool it
  executes (one reference tool). AgentShield cannot stop a runtime that does not ask, or ignores the decision, for any
  other tool.
- Detection figures come only from the repository's synthetic evaluation set and are quoted with their caveats in the
  [coverage matrix](security-coverage-matrix.md).
