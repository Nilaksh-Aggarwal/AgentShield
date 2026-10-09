using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;

namespace AgentShield.IntegrationTests.AiAnalysis;

/// <summary>
/// A scripted Gemini API behind the real adapter's HTTP pipeline (installed as the primary handler of every
/// <see cref="IHttpClientFactory"/> client). Records each request; never touches the network or provider quota.
/// </summary>
internal sealed class FakeGeminiApi(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond)
{
    private readonly Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> _respond = respond;

    public ConcurrentQueue<RecordedRequest> Requests { get; } = new();

    public static FakeGeminiApi Answering(string answerText, string finishReason = "STOP") =>
        Responding(HttpStatusCode.OK, Envelope(answerText, finishReason));

    public static FakeGeminiApi Responding(HttpStatusCode status, string body) =>
        new((_, _) => Task.FromResult(Json(status, body)));

    public static string Envelope(string answerText, string finishReason = "STOP") => JsonSerializer.Serialize(new
    {
        candidates = new[] { new { content = new { role = "model", parts = new[] { new { text = answerText } } }, finishReason } },
    });

    public static string ErrorBody(int code, string status, string message) =>
        JsonSerializer.Serialize(new { error = new { code, message, status } });

    public static HttpResponseMessage Json(HttpStatusCode status, string body) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    /// <summary>A new handler per pipeline (the factory owns and disposes handlers); all share this API's script.</summary>
    public HttpMessageHandler CreateHandler() => new Handler(this);

    internal sealed record RecordedRequest(Uri Uri, IReadOnlyDictionary<string, string> Headers, string Body);

    private sealed class Handler(FakeGeminiApi api) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
            api.Requests.Enqueue(new RecordedRequest(
                request.RequestUri!,
                request.Headers.ToDictionary(header => header.Key, header => string.Join(',', header.Value), StringComparer.OrdinalIgnoreCase),
                body));
            return await api._respond(request, cancellationToken);
        }
    }
}
