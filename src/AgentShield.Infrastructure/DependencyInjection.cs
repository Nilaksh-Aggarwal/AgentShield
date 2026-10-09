using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Application.Abstractions.Caching;
using AgentShield.Application.Abstractions.Context;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Common.Health;
using AgentShield.Infrastructure.Agents;
using AgentShield.Infrastructure.AiCapacity;
using AgentShield.Infrastructure.Caching;
using AgentShield.Infrastructure.Persistence;
using AgentShield.Infrastructure.SecurityEvents;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AgentShield.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configuration);

        AddCaching(services, configuration);
        AddPersistence(services, configuration);
        AddAiCapacity(services, configuration);
        AddAgentDirectory(services, configuration);
        AddToolApprovals(services, configuration);

        services.AddMarkedServices(typeof(DependencyInjection).Assembly);

        return services;
    }

    /// <summary>
    /// Whether a PostgreSQL connection string is configured. When it is not, persistence is not
    /// registered and the readiness probe does not check the database.
    /// </summary>
    public static bool IsDatabaseConfigured(IConfiguration configuration)
    {
        ArgumentNullException.ThrowIfNull(configuration);
        return !string.IsNullOrWhiteSpace(configuration.GetConnectionString(DatabaseOptions.ConnectionStringName));
    }

    /// <summary>
    /// Whether security events, the audit trail, reach the log at the lowest level they are written at (an Allow): the
    /// firewall's security events, the agent action authorizations, the tool gateway's entries and people's approval decisions.
    /// When they do not, decisions are made (and tools run) without any audit record.
    /// </summary>
    public static bool IsSecurityAuditLogEnabled(ILoggerFactory loggerFactory)
    {
        ArgumentNullException.ThrowIfNull(loggerFactory);
        return loggerFactory.CreateLogger<LoggingSecurityEventSink>().IsEnabled(LoggingSecurityEventSink.AuditLevel)
            && loggerFactory.CreateLogger<LoggingAgentActionEventSink>().IsEnabled(LoggingAgentActionEventSink.AuditLevel)
            && loggerFactory.CreateLogger<LoggingToolGatewayEventSink>().IsEnabled(LoggingToolGatewayEventSink.AuditLevel)
            && loggerFactory.CreateLogger<LoggingToolApprovalEventSink>().IsEnabled(LoggingToolApprovalEventSink.AuditLevel);
    }

    private static void AddCaching(IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<CacheOptions>()
            .Bind(configuration.GetSection(CacheOptions.SectionName))
            .Validate(options => options.DefaultExpiration > TimeSpan.Zero, "Cache:DefaultExpiration must be positive.")
            .Validate(options => options.SizeLimit > 0, "Cache:SizeLimit must be positive.")
            .ValidateOnStart();

        services.AddMemoryCache();
        services.AddOptions<MemoryCacheOptions>()
            .Configure<IOptions<CacheOptions>>((memory, cache) => memory.SizeLimit = cache.Value.SizeLimit);

        // Explicit: depends on options and must be a singleton to share the underlying IMemoryCache.
        services.AddSingleton<ICacheService, MemoryCacheService>();
    }

    /// <summary>
    /// The AI capacity gate and the provider circuit breaker with their options (sections <c>Ai:Capacity</c> and
    /// <c>Ai:CircuitBreaker</c>, docs/security/ai-analysis.md, sections 16–17).
    /// </summary>
    /// <remarks>
    /// The gate is always registered: the AI stage asks it only when a provider is registered, so with AI disabled it
    /// is never used. Its options are validated at startup only when <c>Ai:Enabled</c> is true (the switch owned by the
    /// AI layer's <c>AiOptions</c>; read here, not duplicated), so capacity settings never stop a disabled application.
    /// </remarks>
    private static void AddAiCapacity(IServiceCollection services, IConfiguration configuration)
    {
        var aiEnabled = configuration.GetSection("Ai").GetValue<bool>("Enabled");

        services.AddOptions<AiCapacityOptions>()
            .Bind(configuration.GetSection(AiCapacityOptions.SectionName))
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<AiCapacityOptions>>(provider =>
            new AiCapacityOptionsValidator(aiEnabled, provider.GetRequiredService<IApiClientDirectory>()));

        // Explicit: needs options, the client directory and one shared state for the process (singleton).
        services.AddSingleton<IAiCapacityGate, InMemoryAiCapacityGate>();

        // The provider circuit breaker (Ai:CircuitBreaker, section 17): one circuit per process, validated like the budget.
        services.AddOptions<AiCircuitBreakerOptions>()
            .Bind(configuration.GetSection(AiCircuitBreakerOptions.SectionName))
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<AiCircuitBreakerOptions>>(new AiCircuitBreakerOptionsValidator(aiEnabled));
        services.AddSingleton<IAiCircuitBreaker, InMemoryAiCircuitBreaker>();
    }

    /// <summary>
    /// The agents this deployment knows (section <c>AgentAuthorization</c>,
    /// docs/decisions/0020-agent-action-authorization-boundary.md): validated at startup against the tool catalogue and the
    /// configured clients, then read once into an immutable directory.
    /// </summary>
    private static void AddAgentDirectory(IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<AgentDirectoryOptions>()
            .Bind(configuration.GetSection(AgentDirectoryOptions.SectionName))
            .ValidateOnStart();
        services.AddSingleton<IValidateOptions<AgentDirectoryOptions>, AgentDirectoryOptionsValidator>();

        // Explicit: built from options, one immutable directory for the process.
        services.AddSingleton<IAgentDirectory, ConfiguredAgentDirectory>();
    }

    /// <summary>
    /// People's approvals of held tool calls (section <c>ToolApprovals</c>, ADR 0023): in memory, bounded, per process, with
    /// a validated lifetime.
    /// </summary>
    private static void AddToolApprovals(IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<ToolApprovalOptions>()
            .Bind(configuration.GetSection(ToolApprovalOptions.SectionName))
            .Validate(options => options.LifetimeSeconds is >= 1 and <= 86_400, "ToolApprovals:LifetimeSeconds must be between 1 and 86400.")
            .ValidateOnStart();

        // Explicit: built from options, one store for the process (approvals must survive the request that created them).
        services.AddSingleton<IToolApprovalStore, InMemoryToolApprovalStore>();
    }

    private static void AddPersistence(IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<DatabaseOptions>()
            .Bind(configuration.GetSection(DatabaseOptions.SectionName))
            .Validate(options => options.CommandTimeoutSeconds is > 0 and <= 600, "Database:CommandTimeoutSeconds must be between 1 and 600.")
            .ValidateOnStart();

        if (!IsDatabaseConfigured(configuration))
        {
            return;
        }

        var connectionString = configuration.GetConnectionString(DatabaseOptions.ConnectionStringName);

        // Explicit: DbContext requires provider configuration. No EF retry strategy is enabled —
        // retries are only safe for idempotent work and are opted into per feature.
        services.AddDbContext<AgentShieldDbContext>((provider, builder) =>
        {
            var database = provider.GetRequiredService<IOptions<DatabaseOptions>>().Value;
            builder.UseNpgsql(connectionString, npgsql => npgsql.CommandTimeout(database.CommandTimeoutSeconds));
        });

        services.AddHealthChecks()
            .AddDbContextCheck<AgentShieldDbContext>("postgresql", tags: [HealthCheckTags.Ready]);
    }
}
