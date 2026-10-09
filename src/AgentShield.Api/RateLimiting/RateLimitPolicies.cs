namespace AgentShield.Api.RateLimiting;

/// <summary>Named rate-limit policies. Endpoints reference a name; limits come from <see cref="RateLimitingOptions"/>.</summary>
public static class RateLimitPolicies
{
    /// <summary>Strict limit for the firewall analysis endpoint (<see cref="RateLimitingOptions.Firewall"/>).</summary>
    public const string Firewall = "Firewall";

    /// <summary>Generous limit for every other endpoint except liveness (<see cref="RateLimitingOptions.Standard"/>).</summary>
    public const string Standard = "Standard";
}
