using System.Net;
using System.Text;
using System.Text.Json;
using AgentShield.Evaluation.Dataset;

namespace AgentShield.Evaluation.Hosting;

/// <summary>
/// A local stand-in for Gemini (<c>simulate</c> only): answers in Gemini's envelope, with one High finding for fixtures
/// whose label expects one and none otherwise. It checks the runner, not the model; its numbers mean nothing.
/// </summary>
internal static class SimulatedGemini
{
    public static readonly FakeTransport Transport = (_, fixture, _) =>
    {
        var findings = new List<object>();
        if (fixture is { ExpectAiFinding: true, ExpectedCategories.Count: > 0 })
        {
            var category = fixture.ExpectedCategories[0];
            findings.Add(new { category, code = category + ".AiDetected", severity = "High", confidence = 0.9, description = "Simulated finding for a runner self-test." });
        }

        var envelope = JsonSerializer.Serialize(new
        {
            candidates = new[] { new { content = new { role = "model", parts = new[] { new { text = JsonSerializer.Serialize(new { findings }) } } }, finishReason = "STOP" } },
            usageMetadata = new { promptTokenCount = 470, candidatesTokenCount = 40, totalTokenCount = 510 },
            modelVersion = "simulated",
        });
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(envelope, Encoding.UTF8, "application/json") });
    };
}
