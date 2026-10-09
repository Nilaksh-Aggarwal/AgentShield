using Microsoft.EntityFrameworkCore;

namespace AgentShield.Infrastructure.Persistence;

/// <summary>
/// EF Core unit of work for PostgreSQL. Intentionally has no entity sets yet: tables are added
/// together with the feature that needs them (e.g. security events), each with its own
/// <see cref="IEntityTypeConfiguration{TEntity}"/> in this assembly and an EF Core migration.
/// </summary>
public sealed class AgentShieldDbContext(DbContextOptions<AgentShieldDbContext> options) : DbContext(options)
{
    public const string Schema = "agentshield";

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        ArgumentNullException.ThrowIfNull(modelBuilder);

        modelBuilder.HasDefaultSchema(Schema);
        modelBuilder.ApplyConfigurationsFromAssembly(typeof(AgentShieldDbContext).Assembly);
    }
}
