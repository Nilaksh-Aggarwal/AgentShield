using AgentShield.Application.Abstractions.DependencyInjection;
using FluentValidation;
using Microsoft.Extensions.DependencyInjection;

namespace AgentShield.Application;

public static class DependencyInjection
{
    /// <summary>
    /// Registers application services (marker-based convention) and all FluentValidation validators
    /// declared in this assembly.
    /// </summary>
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        ArgumentNullException.ThrowIfNull(services);

        var assembly = typeof(DependencyInjection).Assembly;

        services.AddMarkedServices(assembly);

        // Validators are stateless: IValidator<TRequest> -> validator, scoped so they may depend on scoped services.
        services.Scan(scan => scan
            .FromAssemblies(assembly)
            .AddClasses(classes => classes.AssignableTo(typeof(IValidator<>)), publicOnly: false)
                .AsImplementedInterfaces(type => type.IsGenericType && type.GetGenericTypeDefinition() == typeof(IValidator<>))
                .WithScopedLifetime());

        return services;
    }
}
