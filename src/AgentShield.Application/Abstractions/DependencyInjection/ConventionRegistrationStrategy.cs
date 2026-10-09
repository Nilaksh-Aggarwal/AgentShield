using Microsoft.Extensions.DependencyInjection;
using Scrutor;

namespace AgentShield.Application.Abstractions.DependencyInjection;

/// <summary>
/// How <see cref="ConventionalRegistrationExtensions.AddMarkedServices"/> adds a convention registration
/// (service type S, implementation I) to a collection that may already contain registrations for S.
/// </summary>
/// <remarks>
/// <list type="number">
/// <item>If I is already registered for S (by the convention or explicitly, with any lifetime), nothing is
/// added: an implementation is never registered twice, and an explicit registration keeps its lifetime.</item>
/// <item>Otherwise the registration is always added, so every implementation of a shared interface
/// (e.g. several <c>IThreatDetector</c>s) is resolved through <c>IEnumerable&lt;S&gt;</c>.</item>
/// <item>It is inserted before the first explicit registration of S, if there is one. The explicit
/// registration therefore stays last and keeps winning single-service resolution (<c>GetService&lt;S&gt;</c>),
/// whether it was made before or after the scan.</item>
/// </list>
/// Scrutor's built-in <c>Skip</c> is not used because it skips by service type: the first implementation of
/// an interface wins and every other one is silently dropped. <c>Append</c> is not used because it would
/// duplicate implementations and let the convention override earlier explicit registrations.
/// </remarks>
internal sealed class ConventionRegistrationStrategy : RegistrationStrategy
{
    public static readonly ConventionRegistrationStrategy Instance = new();

    private ConventionRegistrationStrategy()
    {
    }

    public override void Apply(IServiceCollection services, ServiceDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(descriptor);

        var firstExplicitIndex = -1;
        for (var index = 0; index < services.Count; index++)
        {
            var existing = services[index];
            if (existing.ServiceType != descriptor.ServiceType || existing.IsKeyedService != descriptor.IsKeyedService
                || !Equals(existing.ServiceKey, descriptor.ServiceKey))
            {
                continue;
            }

            if (ImplementationTypeOf(existing) == ImplementationTypeOf(descriptor))
            {
                return;
            }

            if (firstExplicitIndex < 0 && !IsConventionRegistration(existing))
            {
                firstExplicitIndex = index;
            }
        }

        if (firstExplicitIndex < 0)
        {
            services.Add(descriptor);
        }
        else
        {
            services.Insert(firstExplicitIndex, descriptor);
        }
    }

    /// <summary>
    /// A registration counts as made by the convention when it is exactly what the convention would produce:
    /// a type registration of a class whose lifetime marker matches the registration's lifetime.
    /// </summary>
    private static bool IsConventionRegistration(ServiceDescriptor descriptor) =>
        descriptor is { IsKeyedService: false, ImplementationType: { } implementation }
        && MarkerLifetimeOf(implementation) == descriptor.Lifetime;

    private static ServiceLifetime? MarkerLifetimeOf(Type implementation) =>
        typeof(IScopedService).IsAssignableFrom(implementation) ? ServiceLifetime.Scoped
        : typeof(ITransientService).IsAssignableFrom(implementation) ? ServiceLifetime.Transient
        : typeof(ISingletonService).IsAssignableFrom(implementation) ? ServiceLifetime.Singleton
        : null;

    // Factory registrations have no statically known implementation type: they are always treated as distinct
    // (and as explicit). Keyed and non-keyed descriptors expose their implementation through different members.
    private static Type? ImplementationTypeOf(ServiceDescriptor descriptor) => descriptor.IsKeyedService
        ? descriptor.KeyedImplementationType ?? descriptor.KeyedImplementationInstance?.GetType()
        : descriptor.ImplementationType ?? descriptor.ImplementationInstance?.GetType();
}
