using System.Globalization;

namespace AgentShield.Evaluation.Run;

/// <summary>
/// Bounds for a real run, checked before anything is sent. The provider's limits are whatever AI Studio shows for the
/// project on the day (Google publishes no free-tier numbers): the operator passes them in, the run stays at or below
/// half of each.
/// </summary>
internal static class SafetyLimits
{
    /// <summary>Hard ceiling for one session (the AgentShield client budget is 160 AI calls per day).</summary>
    public const int MaxCallsCeiling = 150;

    /// <summary>At least this far apart: AgentShield's own client budget is 4 AI calls per minute.</summary>
    public const int MinSpacingSeconds = 15;

    public static IReadOnlyList<string> Check(int maxCalls, int spacingSeconds, int? providerRpm, int? providerRpdRemaining)
    {
        var problems = new List<string>();
        if (maxCalls is < 1 or > MaxCallsCeiling)
        {
            problems.Add(Invariant($"--max-calls must be between 1 and {MaxCallsCeiling}."));
        }

        if (spacingSeconds < MinSpacingSeconds)
        {
            problems.Add(Invariant($"--spacing-seconds must be at least {MinSpacingSeconds}."));
        }

        if (providerRpm is not > 0)
        {
            problems.Add("--provider-rpm (the RPM AI Studio shows for the model) is required.");
        }
        else if (spacingSeconds > 0 && 60.0 / spacingSeconds > providerRpm.Value / 2.0)
        {
            problems.Add(Invariant($"Pacing of {60.0 / spacingSeconds:0.#} calls per minute exceeds half of the provider's {providerRpm} RPM."));
        }

        if (providerRpdRemaining is not > 0)
        {
            problems.Add("--provider-rpd-remaining (today's RPD left in AI Studio) is required.");
        }
        else if (maxCalls > providerRpdRemaining.Value / 2)
        {
            problems.Add(Invariant($"--max-calls {maxCalls} exceeds half of the {providerRpdRemaining} requests left today."));
        }

        return problems;
    }

    private static string Invariant(FormattableString text) => text.ToString(CultureInfo.InvariantCulture);
}
