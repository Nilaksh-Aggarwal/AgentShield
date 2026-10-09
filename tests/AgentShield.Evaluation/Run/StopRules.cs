using System.Globalization;
using AgentShield.Evaluation.Results;

namespace AgentShield.Evaluation.Run;

/// <summary>
/// The session's safety stop rules, applied after every attempt. Nothing is ever retried: a stopped session leaves the
/// remaining fixtures pending for a later, explicitly started session.
/// </summary>
/// <param name="stopOnSlowCalls">
/// Whether a call or stage that completed but came close to the 3 s timeout ends the session (the default). A real run may
/// switch it off (<c>--continue-after-slow-calls</c>): a completed slow call is a valid result, and the failures it warns
/// of (a timeout, an unavailable provider, two failures in a row) still stop the session.
/// </param>
internal sealed class StopRules(bool stopOnSlowCalls = true)
{
    /// <summary>A Gemini call this slow is close to the 3 s stage timeout.</summary>
    public const double SlowProviderCallMs = 2_500;

    /// <summary>An AI stage this slow (after the first call, which includes one-time warm-up) is close to the timeout.</summary>
    public const double SlowStageMs = 2_700;

    private int _serverErrors;
    private int _failuresInARow;
    private bool _firstCallDone;

    /// <param name="attempt">The attempt just recorded.</param>
    /// <param name="refusedByObserver">Provider requests the outbound observer refused during this attempt.</param>
    /// <returns>Why the session must stop now, or <see langword="null"/>.</returns>
    public string? After(AttemptRecord attempt, int refusedByObserver)
    {
        ArgumentNullException.ThrowIfNull(attempt);

        if (refusedByObserver > 0)
        {
            return "a provider request outside the plan was refused before sending";
        }

        if (attempt.ApiStatus != 200)
        {
            return string.Create(CultureInfo.InvariantCulture, $"HTTP {attempt.ApiStatus} from the AgentShield API");
        }

        if (!attempt.ProviderCallAllowed)
        {
            return attempt.ProviderCallCount > 0 ? "a deterministic Block reached the provider" : null;
        }

        var call = attempt.ProviderCall;
        var firstCall = !_firstCallDone;
        _firstCallDone |= attempt.ProviderCallCount > 0;
        if (call?.HttpStatus == 429 || attempt.AiStatus == "RateLimited")
        {
            return "HTTP 429 from Gemini (rate limited)";
        }

        if (call?.HttpStatus >= 500 || attempt.AiStatus == "Unavailable")
        {
            _serverErrors++;
        }

        _failuresInARow = attempt.AiStatus == "Completed" ? 0 : _failuresInARow + 1;
        return _serverErrors >= 2 ? "second HTTP 5xx / unavailable answer from Gemini"
            : attempt.AiStatus == "TimedOut" ? "AI analysis timed out"
            : stopOnSlowCalls && call?.DurationMs >= SlowProviderCallMs ? "Gemini call at or above 2,500 ms"
            : stopOnSlowCalls && !firstCall && attempt.AiStageMs >= SlowStageMs ? "AI stage at or above 2,700 ms"
            : attempt.CircuitAfter is { } circuit && circuit != "Closed" ? "circuit " + circuit
            : _failuresInARow >= 2 ? "two failed AI analyses in a row"
            : null;
    }
}
