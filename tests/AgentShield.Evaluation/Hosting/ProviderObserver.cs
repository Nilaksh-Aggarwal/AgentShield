using System.Collections.Concurrent;
using System.Text;
using System.Text.Json;
using AgentShield.Evaluation.Dataset;
using AgentShield.Evaluation.Results;

namespace AgentShield.Evaluation.Hosting;

/// <summary>A fake provider: answers a request without any network (tests and simulations).</summary>
internal delegate Task<HttpResponseMessage> FakeTransport(HttpRequestMessage request, Fixture? fixture, CancellationToken cancellationToken);

/// <summary>What the outbound observer allows and what it saw. Shared by every handler instance of one host.</summary>
internal sealed class ObserverState(int maxCalls, TimeProvider clock, FakeTransport? fakeTransport)
{
    private int _taken;
    private int _refused;
    private int _inFlight;
    private volatile bool _sendAllowed;

    /// <summary>Hard cap on provider calls for the host's lifetime; requests beyond it are refused before sending.</summary>
    public int MaxCalls { get; } = maxCalls;

    public TimeProvider Clock { get; } = clock;

    /// <summary>When set, the observer answers from it and never forwards to the network.</summary>
    public FakeTransport? FakeTransport { get; } = fakeTransport;

    /// <summary>True only while the runner sends a fixture that may call the provider.</summary>
    public bool SendAllowed
    {
        get => _sendAllowed;
        set => _sendAllowed = value;
    }

    public Fixture? Current { get; set; }

    public ConcurrentQueue<ProviderCall> Calls { get; } = new();

    public int Refused => Volatile.Read(ref _refused);

    /// <summary>Calls sent and not yet ended (a call the stage abandoned at its timeout ends later).</summary>
    public int InFlight => Volatile.Read(ref _inFlight);

    public bool TryTakeSlot()
    {
        if (SendAllowed && Interlocked.Increment(ref _taken) <= MaxCalls)
        {
            Interlocked.Increment(ref _inFlight);
            return true;
        }

        Interlocked.Increment(ref _refused);
        return false;
    }

    public void Refuse() => Interlocked.Increment(ref _refused);

    public void Ended(ProviderCall call)
    {
        Calls.Enqueue(call);
        Interlocked.Decrement(ref _inFlight);
    }
}

/// <summary>A provider call as observed. The answer and descriptions stay in memory for the leak check only.</summary>
internal sealed class ProviderCall(string? fixtureId)
{
    public string? FixtureId { get; } = fixtureId;

    public int? HttpStatus { get; set; }

    public double DurationMs { get; set; }

    public int? PromptTokens { get; set; }

    public int? CandidateTokens { get; set; }

    public int? ThoughtTokens { get; set; }

    public int? TotalTokens { get; set; }

    public string? FinishReason { get; set; }

    public string? ModelVersion { get; set; }

    public bool? AnswerHasOnlyFindings { get; set; }

    public int? AnswerFindingCount { get; set; }

    public string? AnswerWithFindings { get; set; }

    public List<string> Descriptions { get; } = [];

    public ProviderCallRecord ToRecord() => new(
        HttpStatus is null ? ProviderOutcome.NoResponse : ProviderOutcome.Response,
        HttpStatus,
        Math.Round(DurationMs, 1),
        PromptTokens,
        CandidateTokens,
        ThoughtTokens,
        TotalTokens,
        FinishReason,
        ModelVersion,
        AnswerHasOnlyFindings,
        AnswerFindingCount);
}

/// <summary>
/// Outbound handler on every typed client. Lets through only <c>generateContent</c> to the pinned Gemini host, only while
/// the runner allows it and below the hard cap; refuses anything else before it is sent (the adapter sees a network
/// failure). With a fake transport it never forwards anything.
/// </summary>
internal sealed class ProviderObserver(ObserverState state) : DelegatingHandler
{
    public const string GeminiHost = "generativelanguage.googleapis.com";

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var uri = request.RequestUri;
        var generateContent = uri is not null
            && uri.Host.Equals(GeminiHost, StringComparison.OrdinalIgnoreCase)
            && uri.AbsolutePath.EndsWith(":generateContent", StringComparison.Ordinal);
        if (!generateContent)
        {
            state.Refuse();
            throw new HttpRequestException("Refused by the evaluation runner before sending.");
        }

        if (!state.TryTakeSlot())
        {
            throw new HttpRequestException("Refused by the evaluation runner before sending.");
        }

        var fixture = state.Current;
        var call = new ProviderCall(fixture?.Id);
        var started = state.Clock.GetTimestamp();
        try
        {
            var response = state.FakeTransport is { } fake
                ? await fake(request, fixture, cancellationToken)
                : await base.SendAsync(request, cancellationToken);
            call.HttpStatus = (int)response.StatusCode;
            if (response.IsSuccessStatusCode)
            {
                await response.Content.LoadIntoBufferAsync(cancellationToken);
                Inspect(call, await response.Content.ReadAsStringAsync(cancellationToken));
            }

            return response;
        }
        finally
        {
            // Recorded however the call ended; a call cancelled at the timeout has no status.
            call.DurationMs = state.Clock.GetElapsedTime(started).TotalMilliseconds;
            state.Ended(call);
        }
    }

    private static void Inspect(ProviderCall call, string body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            if (root.TryGetProperty("usageMetadata", out var usage))
            {
                call.PromptTokens = Int(usage, "promptTokenCount");
                call.CandidateTokens = Int(usage, "candidatesTokenCount");
                call.ThoughtTokens = Int(usage, "thoughtsTokenCount");
                call.TotalTokens = Int(usage, "totalTokenCount");
            }

            call.ModelVersion = root.TryGetProperty("modelVersion", out var version) && version.ValueKind == JsonValueKind.String ? version.GetString() : null;
            if (!root.TryGetProperty("candidates", out var candidates) || candidates.ValueKind != JsonValueKind.Array || candidates.GetArrayLength() == 0)
            {
                return;
            }

            var candidate = candidates[0];
            call.FinishReason = candidate.TryGetProperty("finishReason", out var reason) && reason.ValueKind == JsonValueKind.String ? reason.GetString() : null;
            var answer = new StringBuilder();
            if (candidate.TryGetProperty("content", out var content) && content.TryGetProperty("parts", out var parts))
            {
                foreach (var part in parts.EnumerateArray())
                {
                    var thought = part.TryGetProperty("thought", out var flag) && flag.ValueKind == JsonValueKind.True;
                    if (!thought && part.TryGetProperty("text", out var text) && text.ValueKind == JsonValueKind.String)
                    {
                        answer.Append(text.GetString());
                    }
                }
            }

            InspectAnswer(call, answer.ToString());
        }
        catch (JsonException)
        {
            // Not a JSON envelope: the adapter reports it (malformed); nothing to record here.
        }
    }

    private static void InspectAnswer(ProviderCall call, string answer)
    {
        try
        {
            using var parsed = JsonDocument.Parse(answer);
            var root = parsed.RootElement;
            call.AnswerHasOnlyFindings = root.ValueKind == JsonValueKind.Object && root.EnumerateObject().All(property => property.Name == "findings");
            if (!root.TryGetProperty("findings", out var findings) || findings.ValueKind != JsonValueKind.Array)
            {
                return;
            }

            call.AnswerFindingCount = findings.GetArrayLength();
            if (call.AnswerFindingCount > 0)
            {
                call.AnswerWithFindings = answer;
            }

            foreach (var finding in findings.EnumerateArray())
            {
                if (finding.ValueKind == JsonValueKind.Object && finding.TryGetProperty("description", out var description)
                    && description.ValueKind == JsonValueKind.String && description.GetString() is { Length: >= 8 } value)
                {
                    call.Descriptions.Add(value);
                }
            }
        }
        catch (JsonException)
        {
            call.AnswerHasOnlyFindings = false;
        }
    }

    private static int? Int(JsonElement element, string name) =>
        element.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var number) ? number : null;
}
