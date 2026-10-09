using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.Globalization;
using System.Reflection;
using System.Text;
using System.Text.Json;
using AgentShield.AI;
using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Evaluation.Results;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Serilog.Core;
using Serilog.Events;

namespace AgentShield.Evaluation.Hosting;

internal sealed record HostSettings(bool AiEnabled, IReadOnlyList<KeyValuePair<string, string>> Settings, TimeProvider? Clock);

/// <summary>
/// The real API in memory (Development environment, real composition, committed configuration plus the settings given).
/// Only observers are added: a log sink, the outbound <see cref="ProviderObserver"/>, a meter listener.
/// </summary>
internal sealed class EvaluationHost : IAsyncDisposable
{
    public const string DevelopmentKey = "agentshield-development-only-key-not-a-secret";
    public const string Route = "/api/v1/firewall/analyze";

    private readonly Factory _factory;

    private EvaluationHost(Factory factory, HttpClient client, MetricsRecorder metrics)
    {
        _factory = factory;
        Client = client;
        Metrics = metrics;
    }

    public HttpClient Client { get; }

    public CaptureSink Sink => _factory.Sink;

    public ObserverState Observer => _factory.Observer;

    public MetricsRecorder Metrics { get; }

    public IServiceProvider Services => _factory.Services;

    public static EvaluationHost Start(HostSettings settings, ObserverState observer)
    {
        ArgumentNullException.ThrowIfNull(settings);
        if (Environment.GetEnvironmentVariable(ContentRootVariable) is null)
        {
            Environment.SetEnvironmentVariable(ContentRootVariable, Path.Combine(Paths.Repository, "src", "AgentShield.Api"));
        }

        var factory = new Factory(settings, observer, new CaptureSink());
        var client = factory.CreateClient();
        return new EvaluationHost(factory, client, new MetricsRecorder(factory.Services.GetRequiredService<IMeterFactory>()));
    }

    public async ValueTask DisposeAsync()
    {
        Metrics.Dispose();
        Client.Dispose();
        await _factory.DisposeAsync();
    }

    public async Task<ApiExchange> PostAsync(string? input, string correlationId, bool withKey = true, string? rawBody = null)
    {
        var body = rawBody ?? JsonSerializer.Serialize(new { input });
        using var request = new HttpRequestMessage(HttpMethod.Post, new Uri(Route, UriKind.Relative))
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        if (withKey)
        {
            request.Headers.Add("X-API-Key", DevelopmentKey);
        }

        request.Headers.Add("X-Correlation-ID", correlationId);
        var started = Observer.Clock.GetTimestamp();
        using var response = await Client.SendAsync(request);
        var text = await response.Content.ReadAsStringAsync();
        var headers = string.Join("\n", response.Headers.Concat(response.Content.Headers).Select(header => header.Key + ": " + string.Join(",", header.Value)));
        return new ApiExchange((int)response.StatusCode, text, headers, Observer.Clock.GetElapsedTime(started).TotalMilliseconds);
    }

    /// <summary>Budgets and circuit state, read by reflection (observation only; null or "unknown" if the shape changed).</summary>
    public GateSnapshot Snapshot()
    {
        var gate = Services.GetService<IAiCapacityGate>();
        var breaker = Services.GetService<IAiCircuitBreaker>();
        const BindingFlags Flags = BindingFlags.NonPublic | BindingFlags.Instance;

        long? Used(string field)
        {
            var budget = gate?.GetType().GetField(field, Flags)?.GetValue(gate);
            return budget?.GetType().GetProperty("Used")?.GetValue(budget) as long?;
        }

        var circuit = breaker?.GetType().GetProperty("State", Flags)?.GetValue(breaker)?.ToString() ?? "unknown";
        return new GateSnapshot(Used("_perMinute"), Used("_perDay"), Used("_inputTokensPerMinute"), gate?.GetType().GetProperty("InFlight", Flags)?.GetValue(gate) as int?, circuit);
    }

    public static string SystemInstruction() =>
        typeof(AiOptions).Assembly.GetType("AgentShield.AI.Gemini.GeminiRequest")?
            .GetField("SystemInstruction", BindingFlags.Public | BindingFlags.Static)?.GetRawConstantValue() as string
        ?? throw new InvalidOperationException("GeminiRequest.SystemInstruction not found.");

    private const string ContentRootVariable = "ASPNETCORE_TEST_CONTENTROOT_AGENTSHIELD_API";

    private sealed class Factory(HostSettings settings, ObserverState observer, CaptureSink sink) : WebApplicationFactory<Program>
    {
        public ObserverState Observer { get; } = observer;

        public CaptureSink Sink { get; } = sink;

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.UseSetting("Ai:Enabled", settings.AiEnabled ? "true" : "false");

            // Committed Development sinks; Information and above, as in the test hosts. The file sink writes to logs/
            // relative to the working directory (the CLI points it at a temporary folder; everything is leak-checked).
            builder.UseSetting("Serilog:MinimumLevel:Default", "Information");
            foreach (var setting in settings.Settings)
            {
                builder.UseSetting(setting.Key, setting.Value);
            }

            builder.ConfigureTestServices(services =>
            {
                services.AddSingleton<ILogEventSink>(Sink);
                if (settings.Clock is { } clock)
                {
                    services.AddSingleton<TimeProvider>(clock);
                }

                services.ConfigureHttpClientDefaults(client => client.AddHttpMessageHandler(() => new ProviderObserver(Observer)));
            });
        }
    }
}

internal sealed record ApiExchange(int Status, string Body, string Headers, double Milliseconds);

internal sealed record GateSnapshot(long? RequestsPerMinute, long? RequestsPerDay, long? TokensPerMinute, int? InFlight, string Circuit);

internal sealed class CaptureSink : ILogEventSink
{
    public ConcurrentQueue<LogEvent> Events { get; } = new();

    public void Emit(LogEvent logEvent) => Events.Enqueue(logEvent);
}

internal sealed record Measurement(string Instrument, long Value, string Tags);

/// <summary>Measurements of this host's <c>AgentShield.AI</c> meters only (other hosts in the process are ignored).</summary>
internal sealed class MetricsRecorder : IDisposable
{
    private readonly MeterListener _listener = new();

    public MetricsRecorder(IMeterFactory scope)
    {
        _listener.InstrumentPublished = (instrument, listener) =>
        {
            if (instrument.Meter.Name == "AgentShield.AI" && ReferenceEquals(instrument.Meter.Scope, scope))
            {
                listener.EnableMeasurementEvents(instrument);
            }
        };
        _listener.SetMeasurementEventCallback<long>((instrument, value, tags, _) =>
        {
            var text = new StringBuilder();
            foreach (var tag in tags)
            {
                text.Append(tag.Key).Append('=').Append(Convert.ToString(tag.Value, CultureInfo.InvariantCulture)).Append(';');
            }

            Measurements.Enqueue(new Measurement(instrument.Name, value, text.ToString()));
        });
        _listener.Start();
    }

    public ConcurrentQueue<Measurement> Measurements { get; } = new();

    public void Dispose() => _listener.Dispose();
}

/// <summary>Reads the security-event log entries the analyses produce.</summary>
internal static class Logs
{
    public static string? Scalar(LogEvent? entry, string name) =>
        entry is not null && entry.Properties.TryGetValue(name, out var value) && value is ScalarValue scalar
            ? Convert.ToString(scalar.Value, CultureInfo.InvariantCulture)
            : null;

    public static double? Double(LogEvent? entry, string name) =>
        entry is not null && entry.Properties.TryGetValue(name, out var value) && value is ScalarValue { Value: double number } ? number : null;

    public static IReadOnlyList<string> Sequence(LogEvent? entry, string name) =>
        entry is not null && entry.Properties.TryGetValue(name, out var value) && value is SequenceValue sequence
            ? [.. sequence.Elements.OfType<ScalarValue>().Select(item => Convert.ToString(item.Value, CultureInfo.InvariantCulture) ?? string.Empty)]
            : [];

    public static int? EventId(LogEvent entry) =>
        entry.Properties.TryGetValue("EventId", out var value) && value is StructureValue structure
            && structure.Properties.FirstOrDefault(property => property.Name == "Id")?.Value is ScalarValue { Value: int id }
            ? id
            : null;

    public static string Render(LogEvent entry) =>
        entry.RenderMessage(CultureInfo.InvariantCulture) + "\n" + entry.MessageTemplate.Text + "\n"
        + string.Join("\n", entry.Properties.Select(property => property.Key + "=" + property.Value)) + "\n" + entry.Exception;
}

/// <summary>The analysis an API response and its security-event log entry describe.</summary>
internal sealed record Analysis(
    string? Decision,
    string? PolicyRule,
    string? RiskLevel,
    int? RiskScore,
    IReadOnlyList<FindingRecord> Findings,
    string? AiStatus,
    string? AiFailureRule,
    double? AiStageMs,
    double? AnalysisMs,
    IReadOnlyList<int> WarningEventIds)
{
    public static Analysis From(ApiExchange exchange, CaptureSink sink, string correlationId)
    {
        ArgumentNullException.ThrowIfNull(exchange);
        ArgumentNullException.ThrowIfNull(sink);

        string? decision = null, riskLevel = null, eventId = null;
        int? riskScore = null;
        var findings = new List<FindingRecord>();
        if (exchange.Status == 200)
        {
            using var document = JsonDocument.Parse(exchange.Body);
            var data = document.RootElement.GetProperty("data");
            decision = data.GetProperty("decision").GetString();
            riskLevel = data.GetProperty("risk").GetProperty("level").GetString();
            riskScore = data.GetProperty("risk").GetProperty("score").GetInt32();
            eventId = data.GetProperty("securityEventId").GetString();
            findings.AddRange(data.GetProperty("findings").EnumerateArray().Select(finding => new FindingRecord(
                finding.GetProperty("code").GetString()!,
                finding.GetProperty("category").GetString()!,
                finding.GetProperty("severity").GetString()!,
                finding.GetProperty("confidence").GetDouble())));
        }

        var securityEvent = eventId is null ? null : sink.Events.LastOrDefault(entry => Logs.Scalar(entry, "SecurityEventId") == eventId);
        var warnings = sink.Events
            .Where(entry => Logs.Scalar(entry, "CorrelationId") == correlationId && Logs.EventId(entry) is 1100 or 1101 or 1200 or 1201 or 1300)
            .Select(entry => Logs.EventId(entry)!.Value)
            .ToList();
        return new Analysis(
            decision,
            Logs.Scalar(securityEvent, "PolicyRule"),
            riskLevel,
            riskScore,
            findings,
            Logs.Scalar(securityEvent, "AiStatus"),
            Logs.Sequence(securityEvent, "RuleIds").FirstOrDefault(rule => rule.StartsWith("AI-FAIL/", StringComparison.Ordinal)),
            Logs.Double(securityEvent, "AiDurationMs"),
            Logs.Double(securityEvent, "DurationMs"),
            warnings);
    }
}

internal static class Paths
{
    public static string Repository { get; } = Find();

    public static string DatasetFile => Path.Combine(Repository, "tests", "Evaluation", "ai-security-evaluation-set.json");

    public static string DefaultResults => Path.Combine(Repository, "tests", "Evaluation", "results");

    public static string ApiAppsettings => Path.Combine(Repository, "src", "AgentShield.Api", "appsettings.json");

    private static string Find()
    {
        foreach (var start in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
        {
            for (var directory = new DirectoryInfo(start); directory is not null; directory = directory.Parent)
            {
                if (File.Exists(Path.Combine(directory.FullName, "AgentShield.slnx")))
                {
                    return directory.FullName;
                }
            }
        }

        throw new InvalidOperationException("Run the evaluation from inside the AgentShield repository.");
    }
}
