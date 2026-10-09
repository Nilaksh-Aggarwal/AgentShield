namespace AgentShield.Infrastructure.Persistence;

/// <summary>
/// Database tuning options. The connection string itself is read from
/// <c>ConnectionStrings:AgentShield</c> (user secrets / environment variable
/// <c>ConnectionStrings__AgentShield</c>) and must never be committed.
/// </summary>
public sealed class DatabaseOptions
{
    public const string SectionName = "Database";

    public const string ConnectionStringName = "AgentShield";

    public int CommandTimeoutSeconds { get; set; } = 30;
}
