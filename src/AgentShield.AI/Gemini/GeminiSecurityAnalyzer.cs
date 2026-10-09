using System.Collections.Frozen;
using System.Net;
using System.Text;
using System.Text.Json;
using AgentShield.AI.StructuredOutput;
using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Common.Results;
using Google.GenAI;
using Google.GenAI.Types;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AgentShield.AI.Gemini;

/// <summary>
/// <see cref="IAiSecurityAnalyzer"/> for the Google Gemini API (Gemini Developer API, API key), built on the official
/// Google Gen AI SDK (<c>Google.GenAI</c>). Returns the model's raw structured output or an
/// <see cref="AiAnalysisErrors"/> failure; validation, the hard timeout and failure handling stay in the Security
/// layer's AI analysis stage.
/// </summary>
/// <remarks>
/// <para>A typed <see cref="HttpClient"/> (registered in <c>AddAI</c>, transient) with the configured timeout and a
/// response size cap. The SDK <see cref="Client"/> takes that <see cref="HttpClient"/> and disposes it with itself, so
/// each analyzer owns one client for its lifetime (one request scope) and disposes it; the handler is pooled by
/// <see cref="IHttpClientFactory"/>.</para>
/// <para>Hardening beyond the SDK defaults:</para>
/// <list type="bullet">
/// <item>The endpoint is pinned. The SDK would otherwise take its base URL from the <c>GOOGLE_GEMINI_BASE_URL</c>
/// environment variable and send the API key there.</item>
/// <item>Retries are pinned off (<c>Attempts = 1</c>): a completion call is a POST with a cost and a latency budget.</item>
/// <item>Only the first candidate's non-thought text parts are read; the SDK's <c>Text</c> would include thoughts.</item>
/// <item>Provider exception messages contain the provider's error body and are never logged or returned; only the
/// HTTP status code is logged. An exception the adapter does not map leaves it as a
/// <see cref="GeminiAdapterFaultException"/>, without its message.</item>
/// <item>Redirects are not followed (<see cref="ConfigurePrimaryHandler"/>), so the API key never goes to another host.</item>
/// </list>
/// </remarks>
internal sealed partial class GeminiSecurityAnalyzer : IAiSecurityAnalyzer, IDisposable
{
    /// <summary>Gemini Developer API endpoint (the SDK appends the API version and method).</summary>
    public const string Endpoint = "https://generativelanguage.googleapis.com";

    /// <summary>
    /// Largest HTTP response buffered. The answer text itself is capped at
    /// <see cref="AiStructuredOutputParser.MaxResponseBytes"/> (32 KiB); the envelope adds usage metadata and
    /// thought signatures. Larger → <see cref="HttpRequestError.ConfigurationLimitExceeded"/> → malformed.
    /// </summary>
    public const int MaxResponseBytes = 256 * 1024;

    /// <summary>Finish reasons that mean the model or its safety system declined to produce the answer.</summary>
    private static readonly FrozenSet<string> RefusalReasons = new[]
    {
        FinishReason.Safety, FinishReason.Recitation, FinishReason.Language, FinishReason.Blocklist,
        FinishReason.ProhibitedContent, FinishReason.Spii, FinishReason.ImageSafety,
        FinishReason.ImageProhibitedContent, FinishReason.ImageRecitation,
    }.Select(reason => reason.Value).ToFrozenSet(StringComparer.Ordinal);

    private static readonly FrozenSet<string> KnownFinishReasons =
        FinishReason.AllValues.Select(reason => reason.Value).ToFrozenSet(StringComparer.Ordinal);

    private readonly HttpClient _httpClient;
    private readonly Client _client;
    private readonly string _model;
    private readonly TimeProvider _timeProvider;
    private readonly ILogger<GeminiSecurityAnalyzer> _logger;

    public GeminiSecurityAnalyzer(
        HttpClient httpClient,
        IOptions<AiOptions> options,
        TimeProvider timeProvider,
        ILogger<GeminiSecurityAnalyzer> logger)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(timeProvider);
        ArgumentNullException.ThrowIfNull(logger);

        var settings = options.Value;
        if (string.IsNullOrWhiteSpace(settings.Gemini?.ApiKey))
        {
            // Startup validation requires the key whenever AI is enabled; reaching this is a composition bug.
            throw new InvalidOperationException($"The Gemini API key ({AiOptions.GeminiApiKeyConfigurationKey}) is not configured.");
        }

        _httpClient = httpClient;
        _model = settings.Model;
        _timeProvider = timeProvider;
        _logger = logger;

        // Explicit enterprise/vertexAI = false: the Gemini Developer API with an API key, whatever the environment says.
        _client = new Client(
            enterprise: false,
            vertexAI: false,
            apiKey: settings.Gemini?.ApiKey,
            httpOptions: new HttpOptions
            {
                BaseUrl = Endpoint,
                RetryOptions = new HttpRetryOptions { Attempts = 1 },
            },
            clientOptions: new ClientOptions { HttpClientFactory = () => httpClient });
    }

    public string Provider => AiOptions.GeminiProvider;

    public string Model => _model;

    public async Task<Result<AiAnalysisOutput>> AnalyzeAsync(AiAnalysisRequest request, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);

        var started = _timeProvider.GetTimestamp();
        var estimatedInputTokens = GeminiRequest.EstimateInputTokens(request);

        // Built outside the try: a fault in AgentShield's own request code must fail closed (500), not be read as a
        // malformed provider answer below.
        var userTurn = GeminiRequest.UserTurn(request);
        var config = GeminiRequest.Config();
        GenerateContentResponse response;
        try
        {
            response = await _client.Models.GenerateContentAsync(_model, userTurn, config, cancellationToken);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            // HttpClient.Timeout (the provider timeout) expired. Caller or stage cancellation propagates instead.
            return Fail(AiAnalysisErrors.Timeout(), started, httpStatus: null);
        }
        catch (ApiException exception)
        {
            // ClientError (4xx) / ServerError (5xx). The message holds the provider's error body: never used.
            return Fail(ErrorForStatus(exception.StatusCode), started, exception.StatusCode);
        }
        catch (HttpRequestException exception) when (exception.HttpRequestError == HttpRequestError.ConfigurationLimitExceeded)
        {
            // The response exceeded MaxResponseBytes.
            return Fail(AiAnalysisErrors.MalformedResponse(), started, httpStatus: null);
        }
        catch (HttpRequestException exception) when (exception.StatusCode is { } status)
        {
            // Gemini answered with a status the SDK did not turn into an ApiException (a 3xx: redirects are not followed),
            // so it is classified by that status like any other answer, not as a network failure.
            return Fail(ErrorForStatus((int)status), started, (int)status);
        }
        catch (HttpRequestException)
        {
            // DNS, TLS, connection refused/reset, response ended early: the provider could not be reached.
            return Fail(AiAnalysisErrors.NetworkFailure(), started, httpStatus: null);
        }
        catch (JsonException)
        {
            // A 2xx whose body is not the generateContent envelope.
            return Fail(AiAnalysisErrors.MalformedResponse(), started, httpStatus: null);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidCastException or NotSupportedException
            or InvalidOperationException and not ObjectDisposedException)
        {
            // A response the SDK could not read (duplicate members, an unsupported charset, a null or wrongly typed
            // envelope). The SDK raises general exceptions for these whose messages can carry provider-chosen text: a
            // malformed answer like any other, and the message is never used or logged.
            return Fail(AiAnalysisErrors.MalformedResponse(), started, httpStatus: null);
        }
        catch (Exception exception) when (exception is not OperationCanceledException)
        {
            // Anything else is unexpected and fails the analysis closed (500), but not as it is: its message can carry
            // provider-chosen text (.NET quotes the offending value in FormatException and KeyNotFoundException messages),
            // and the global exception handler logs what reaches it. Only the type names and the stack trace go on.
            throw GeminiAdapterFaultException.From(exception);
        }

        // The token budget reserved the local estimate. If Gemini ever counts more, the estimate is wrong: say so (numbers
        // only) so the budget can be corrected. The answer is still used; nothing is refunded or charged afterwards.
        if (response.UsageMetadata?.PromptTokenCount is { } reportedInputTokens && reportedInputTokens > estimatedInputTokens)
        {
            LogEstimateExceeded(_logger, _model, reportedInputTokens, estimatedInputTokens);
        }

        var answer = ReadAnswer(response, out var finishReason);
        if (answer.IsFailure)
        {
            return Fail(answer.Error, started, httpStatus: null, finishReason);
        }

        var output = AiStructuredOutputParser.Parse(answer.Value);
        return output.IsFailure ? Fail(output.Error, started, httpStatus: null, finishReason) : output;
    }

    /// <inheritdoc />
    /// <remarks>Local: <see cref="GeminiRequest.EstimateInputTokens"/>. Never Gemini's <c>countTokens</c> endpoint.</remarks>
    public long EstimateInputTokens(AiAnalysisRequest request) => GeminiRequest.EstimateInputTokens(request);

    public void Dispose()
    {
        // The SDK disposes the HttpClient only once it has asked for it (on the first call); dispose it either way.
        _client.Dispose();
        _httpClient.Dispose();
    }

    /// <summary>Settings of the typed client: the provider timeout and the response size cap.</summary>
    internal static void ConfigureHttpClient(HttpClient client, AiOptions options)
    {
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(options);

        client.Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds);
        client.MaxResponseContentBufferSize = MaxResponseBytes;
    }

    /// <summary>
    /// Turns off automatic redirects on the typed client's primary handler. .NET sends custom headers such as
    /// <c>x-goog-api-key</c> again on a redirect (it drops only <c>Authorization</c>), so following one would hand the key
    /// to whatever host the response named; pinning the endpoint covers the first request only. A 3xx is then the answer
    /// itself, and a rejected request.
    /// </summary>
    internal static void ConfigurePrimaryHandler(HttpMessageHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);

        switch (handler)
        {
            case SocketsHttpHandler sockets:
                sockets.AllowAutoRedirect = false;
                break;
            case HttpClientHandler client:
                client.AllowAutoRedirect = false;
                break;

            // Any other primary handler is not a network handler of its own (a test transport) and follows nothing.
        }
    }

    /// <summary>
    /// Maps a provider HTTP status to an error by cause. Every failure holds the input for review; the circuit breaker
    /// additionally counts the availability failures (RateLimited, Unavailable, Timeout, network), never a rejected
    /// request (docs/security/ai-analysis.md, section 17).
    /// </summary>
    internal static Error ErrorForStatus(int status) => status switch
    {
        // Rate or quota limit (the free tier has per-minute and per-day quotas).
        (int)HttpStatusCode.TooManyRequests => AiAnalysisErrors.RateLimited(),

        // The provider gave up on this request in time: content can make the model slow, so this is a timeout (Review).
        (int)HttpStatusCode.RequestTimeout or (int)HttpStatusCode.GatewayTimeout => AiAnalysisErrors.Timeout(),

        // Configuration faults (bad, revoked or blocked key, no permission for the project, unknown or retired model).
        // Gemini answered, so it is reachable: waiting does not fix these, and they must not open the process-wide
        // circuit or be reported as an outage. Rejected like an invalid key, which this API reports as 400.
        (int)HttpStatusCode.Unauthorized or (int)HttpStatusCode.Forbidden or (int)HttpStatusCode.NotFound => AiAnalysisErrors.RequestRejected(),

        >= 500 and <= 599 => AiAnalysisErrors.Unavailable(),

        // 400 (also returned for an invalid API key), 413 and every other status: the request carried the content.
        _ => AiAnalysisErrors.RequestRejected(),
    };

    /// <summary>
    /// The answer text of a successful call, or why there is none. A refusal is a blocked prompt or a safety-type finish
    /// reason; anything else that is not one complete candidate (<c>STOP</c>) with text is malformed.
    /// </summary>
    internal static Result<string> ReadAnswer(GenerateContentResponse response, out string? finishReason)
    {
        ArgumentNullException.ThrowIfNull(response);
        finishReason = null;

        if (response.PromptFeedback?.BlockReason is not null)
        {
            finishReason = "PROMPT_BLOCKED";
            return AiAnalysisErrors.Refused();
        }

        if (response.Candidates is not [var candidate])
        {
            return AiAnalysisErrors.MalformedResponse();
        }

        var reason = candidate.FinishReason?.Value;
        finishReason = reason is null ? null : KnownFinishReasons.Contains(reason) ? reason : "UNKNOWN";
        if (reason is not null && RefusalReasons.Contains(reason))
        {
            return AiAnalysisErrors.Refused();
        }

        if (reason != FinishReason.Stop.Value || candidate.Content?.Parts is not { Count: > 0 } parts)
        {
            return AiAnalysisErrors.MalformedResponse();
        }

        var text = new StringBuilder();
        foreach (var part in parts)
        {
            if (part.Thought == true)
            {
                continue;
            }

            // No tools are configured: a function call, file or other non-text part is outside the contract.
            if (part.Text is null)
            {
                return AiAnalysisErrors.MalformedResponse();
            }

            text.Append(part.Text);
        }

        if (text.Length == 0)
        {
            return AiAnalysisErrors.MalformedResponse();
        }

        return text.ToString();
    }

    private Result<AiAnalysisOutput> Fail(Error error, long started, int? httpStatus, string? finishReason = null)
    {
        LogFailure(_logger, _model, error.Code, httpStatus, finishReason, _timeProvider.GetElapsedTime(started).TotalMilliseconds);
        return error;
    }

    // Fixed vocabulary only: error code, HTTP status, known finish reason, model, duration. Never the exception, its
    // message (the provider's error body), the request, the prompt or the answer.
    [LoggerMessage(
        EventId = 1100,
        Level = LogLevel.Warning,
        Message = "Gemini analysis failed: {FailureCategory} (HTTP {HttpStatus}, finish reason {FinishReason}) for model {AiModel} after {DurationMs} ms")]
    private static partial void LogFailure(
        ILogger logger, string aiModel, string failureCategory, int? httpStatus, string? finishReason, double durationMs);

    [LoggerMessage(
        EventId = 1101,
        Level = LogLevel.Warning,
        Message = "Gemini counted {ReportedInputTokens} input tokens for model {AiModel}, more than the conservative estimate of {EstimatedInputTokens} reserved in the AI token budget")]
    private static partial void LogEstimateExceeded(ILogger logger, string aiModel, int reportedInputTokens, long estimatedInputTokens);
}
