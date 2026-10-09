using System.Reflection;
using Microsoft.Extensions.DependencyInjection;

namespace AgentShield.Application.Abstractions.DependencyInjection;

public static class ConventionalRegistrationExtensions
{
    private static readonly Type[] MarkerInterfaces =
        [typeof(IScopedService), typeof(ITransientService), typeof(ISingletonService)];

    /// <summary>
    /// Registers every concrete class in <paramref name="assembly"/> that opts in through a lifetime marker
    /// (<see cref="IScopedService"/>, <see cref="ITransientService"/>, <see cref="ISingletonService"/>)
    /// against the interfaces it implements (excluding the markers themselves).
    /// </summary>
    /// <remarks>
    /// Every implementation of a shared interface is registered (all resolve through <c>IEnumerable&lt;T&gt;</c>),
    /// an implementation is never registered twice for the same interface, and an explicit registration keeps
    /// winning single-service resolution. See <see cref="ConventionRegistrationStrategy"/> for the exact rules.
    /// </remarks>
    public static IServiceCollection AddMarkedServices(this IServiceCollection services, Assembly assembly)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(assembly);

        return services.Scan(scan => scan
            .FromAssemblies(assembly)
            .AddClasses(classes => classes.AssignableTo<IScopedService>(), publicOnly: false)
                .UsingRegistrationStrategy(ConventionRegistrationStrategy.Instance)
                .AsImplementedInterfaces(IsNotMarker)
                .WithScopedLifetime()
            .AddClasses(classes => classes.AssignableTo<ITransientService>(), publicOnly: false)
                .UsingRegistrationStrategy(ConventionRegistrationStrategy.Instance)
                .AsImplementedInterfaces(IsNotMarker)
                .WithTransientLifetime()
            .AddClasses(classes => classes.AssignableTo<ISingletonService>(), publicOnly: false)
                .UsingRegistrationStrategy(ConventionRegistrationStrategy.Instance)
                .AsImplementedInterfaces(IsNotMarker)
                .WithSingletonLifetime());
    }

    private static bool IsNotMarker(Type serviceType) => !MarkerInterfaces.Contains(serviceType);
}
