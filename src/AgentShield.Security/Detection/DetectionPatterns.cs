using System.Text.RegularExpressions;

namespace AgentShield.Security.Detection;

/// <summary>Regex settings shared by every detection pattern (untrusted input: linear time, bounded runtime).</summary>
internal static class DetectionPatterns
{
    /// <summary>
    /// Case-insensitive, culture-invariant and <see cref="RegexOptions.NonBacktracking"/>: matching time is linear in
    /// the input length, so crafted input cannot trigger catastrophic backtracking (ReDoS). Patterns therefore cannot
    /// use lookarounds, backreferences or atomic groups.
    /// </summary>
    public const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking;

    /// <summary>Upper bound per pattern evaluation; a timeout fails the analysis (see <see cref="PatternThreatDetector"/>).</summary>
    public const int TimeoutMilliseconds = 250;
}
