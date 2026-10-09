using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;

namespace AgentShield.SecurityTests.AiAnalysis.Gemini;

/// <summary>
/// Stands in for the Gemini API at the HTTP boundary, below the real SDK: records every request (with its body) and
/// answers with a scripted response. No test reaches the network or consumes provider quota.
/// </summary>
internal sealed class FakeGeminiHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
{
    public ConcurrentQueue<RecordedRequest> Requests { get; } = new();

    public static FakeGeminiHandler Answering(string answerText, string finishReason = "STOP") =>
        Responding(HttpStatusCode.OK, Envelope(answerText, finishReason));

    public static FakeGeminiHandler Responding(HttpStatusCode status, string body) =>
        new((_, _) => Task.FromResult(Json(status, body)));

    /// <summary>The generateContent response envelope around one candidate's answer text.</summary>
    public static string Envelope(string answerText, string finishReason = "STOP") => JsonSerializer.Serialize(new
    {
        candidates = new[] { new { content = new { role = "model", parts = new[] { new { text = answerText } } }, finishReason } },
        modelVersion = "gemini-3.8-flash",
    });

    /// <summary>A Google API error body, as Gemini returns it for 4xx/5xx.</summary>
    public static string ErrorBody(int code, string status, string message) =>
        JsonSerializer.Serialize(new { error = new { code, message, status } });

    public static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        Requests.Enqueue(new RecordedRequest(
            request.Method,
            request.RequestUri!,
            request.Headers.ToDictionary(header => header.Key, header => string.Join(',', header.Value), StringComparer.OrdinalIgnoreCase),
            body));
        return await respond(request, cancellationToken);
    }

    internal sealed record RecordedRequest(HttpMethod Method, Uri Uri, IReadOnlyDictionary<string, string> Headers, string Body)
    {
        public JsonElement Json => JsonDocument.Parse(Body).RootElement;
    }
}
