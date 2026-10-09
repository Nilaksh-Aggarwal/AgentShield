using System.Text.Json.Serialization;

namespace AgentShield.Evaluation.Results;

// Everything written to disk. Fixture IDs, codes, statuses and numbers only: no record has a field that could hold an
// input, a decoded payload, a prompt, a provider answer, a model-written description or a key (tested).

internal sealed record FindingRecord(string Code, string Category, string Severity, double Confidence)
{
    [JsonIgnore]
    public bool FromAi => Code.EndsWith(".AiDetected", StringComparison.Ordinal);
}

/// <summary>How the provider call ended, as seen at the HTTP boundary.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ProviderOutcome>))]
internal enum ProviderOutcome
{
    /// <summary>Gemini answered with an HTTP status (any status).</summary>
    Response,

    /// <summary>Sent, but ended without a response (cancelled at the timeout, network failure).</summary>
    NoResponse,

    /// <summary>Sent, but not observed (Milestone 7 session 1: recorded before the abandoned call ended).</summary>
    NotCaptured,
}

internal sealed record ProviderCallRecord(
    ProviderOutcome Outcome,
    int? HttpStatus,
    double? DurationMs,
    int? PromptTokens,
    int? CandidateTokens,
    int? ThoughtTokens,
    int? TotalTokens,
    string? FinishReason,
    string? ModelVersion,
    bool? AnswerHasOnlyFindings,
    int? AnswerFindingCount);

/// <summary>A fixture analysed with AI off (the deterministic decision every AI attempt is compared with).</summary>
internal sealed record BaselineRecord(
    string FixtureId,
    int ApiStatus,
    string? Decision,
    string? PolicyRule,
    string? RiskLevel,
    int? RiskScore,
    IReadOnlyList<FindingRecord> Findings,
    string? AiStatus);

/// <summary>One fixture sent once in one session. Attempts are appended and never rewritten.</summary>
internal sealed record AttemptRecord(
    string SessionId,
    int Sequence,
    string FixtureId,
    string? StartedUtc,
    string DeterministicDecision,
    bool ProviderCallAllowed,
    int ApiStatus,
    string? Decision,
    string? PolicyRule,
    string? RiskLevel,
    int? RiskScore,
    IReadOnlyList<FindingRecord> Findings,
    string? AiStatus,
    string? AiFailureRule,
    double? AiStageMs,
    double? AnalysisMs,
    double? TotalMs,
    int ProviderCallCount,
    ProviderCallRecord? ProviderCall,
    long EstimatedInputTokens,
    string? Admission,
    string? CircuitBefore,
    string? CircuitAfter,
    bool DescriptionInResponse,
    IReadOnlyList<int> WarningEventIds)
{
    /// <summary>A usable AI result: the AI completed, or was not needed because the deterministic rules block.</summary>
    [JsonIgnore]
    public bool Valid => ApiStatus == 200 && AiStatus is "Completed" or "NotNeeded";

    [JsonIgnore]
    public IReadOnlyList<FindingRecord> AiFindings => [.. Findings.Where(finding => finding.FromAi)];
}

internal sealed record ProbeResult(string Name, int HttpStatus, bool Echoed);

/// <summary>
/// Written immediately before a fixture that may reach the provider is sent (write-ahead). A send record without an
/// attempt record means the process ended while the call was in flight: the request may have reached the provider, so
/// the fixture counts as attempted and is never planned as never-attempted again.
/// </summary>
internal sealed record SendRecord(string SessionId, string FixtureId, string SentUtc);

/// <summary>Where a forbidden value was found (label and counts only, never the value).</summary>
internal sealed record LeakResult(string Label, IReadOnlyDictionary<string, int> Hits);

internal sealed record SessionRecord(
    string SessionId,
    string Mode,
    string StartedUtc,
    string FinishedUtc,
    int DatasetVersion,
    string InputFingerprint,
    string ContentFingerprint,
    string BaselineFingerprint,
    string Subset,
    int MaxCalls,
    int SpacingSeconds,
    int? ProviderRpm,
    int? ProviderRpdRemaining,
    bool ExcludeFailed,
    IReadOnlyDictionary<string, string> Configuration,
    int PlannedFixtures,
    int FixturesSent,
    int ProviderCalls,
    int ProviderRequestsRefused,
    string? StopReason,
    string? StopFixtureId,
    IReadOnlyList<ProbeResult> ErrorProbes,
    int ForbiddenValuesChecked,
    int LeakHits,
    IReadOnlyList<LeakResult> Leaks,
    IReadOnlyDictionary<string, int> WarningEvents,
    string? Note);
