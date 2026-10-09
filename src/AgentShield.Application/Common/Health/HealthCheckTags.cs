namespace AgentShield.Application.Common.Health;

/// <summary>
/// Tags that route health checks to probe endpoints. Any layer registering a health check
/// chooses the probe(s) it participates in.
/// </summary>
public static class HealthCheckTags
{
    /// <summary>The process is alive. Never tag dependency checks (database, LLM provider) as live.</summary>
    public const string Live = "live";

    /// <summary>A dependency the application needs before it can accept traffic.</summary>
    public const string Ready = "ready";
}
