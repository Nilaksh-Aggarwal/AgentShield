using AgentShield.AI;
using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Evaluation.Dataset;
using AgentShield.Evaluation.Hosting;
using AgentShield.Evaluation.Results;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AgentShield.Evaluation.Run;

internal sealed record BaselineRun(IReadOnlyList<BaselineRecord> Records, IReadOnlyList<string> Responses, IReadOnlyList<string> LogEvents, IReadOnlyList<string> Problems);

/// <summary>Every fixture through the real composition with AI off. No provider request can be sent (cap 0).</summary>
internal static class BaselineRunner
{
    public static async Task<BaselineRun> RunAsync(EvaluationDataset dataset)
    {
        ArgumentNullException.ThrowIfNull(dataset);

        var observer = new ObserverState(maxCalls: 0, TimeProvider.System, (_, _, _) => throw new HttpRequestException("No provider call is allowed in the baseline."));
        var records = new List<BaselineRecord>();
        var responses = new List<string>();
        var problems = new List<string>();
        var host = EvaluationHost.Start(new HostSettings(false, [], null), observer);
        await using (host)
        {
            var ai = host.Services.GetRequiredService<IOptions<AiOptions>>().Value;
            using (var scope = host.Services.CreateScope())
            {
                if (ai.Enabled || scope.ServiceProvider.GetService<IAiSecurityAnalyzer>() is not null)
                {
                    return new BaselineRun([], [], [], ["AI is not disabled in the baseline host."]);
                }
            }

            foreach (var fixture in dataset.Fixtures)
            {
                var correlation = "eval-baseline-" + fixture.Id;
                var exchange = await host.PostAsync(fixture.Text, correlation);
                responses.Add(exchange.Body + "\n" + exchange.Headers);
                var analysis = Analysis.From(exchange, host.Sink, correlation);
                records.Add(new BaselineRecord(fixture.Id, exchange.Status, analysis.Decision, analysis.PolicyRule, analysis.RiskLevel, analysis.RiskScore, analysis.Findings, analysis.AiStatus));
                if (exchange.Status != 200 || analysis.AiStatus != "Disabled")
                {
                    problems.Add(fixture.Id + ": baseline analysis did not complete with AI disabled.");
                }
            }
        }

        if (!observer.Calls.IsEmpty || observer.Refused != 0)
        {
            problems.Add("The baseline host attempted a provider request.");
        }

        return new BaselineRun(records, responses, [.. host.Sink.Events.Select(Logs.Render)], problems);
    }
}
