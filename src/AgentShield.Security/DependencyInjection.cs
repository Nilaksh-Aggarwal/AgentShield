using AgentShield.Application.Abstractions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

namespace AgentShield.Security;

public static class DependencyInjection
{
    /// <summary>
    /// Registers deterministic security components (normalisation, detection, risk, policy) that
    /// implement Application abstractions.
    /// </summary>
    public static IServiceCollection AddSecurity(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddMarkedServices(typeof(DependencyInjection).Assembly);

        return services;
    }
}
