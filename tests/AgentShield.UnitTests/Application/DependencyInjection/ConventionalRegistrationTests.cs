using AgentShield.Application.Abstractions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

namespace AgentShield.UnitTests.Application.DependencyInjection;

public interface IScopedSample;

public interface ITransientSample;

public interface ISingletonSample;

public interface IExplicitSample;

public interface IUnmarkedSample;

public interface ISharedSample;

internal sealed class ScopedSample : IScopedSample, IScopedService;

internal sealed class TransientSample : ITransientSample, ITransientService;

internal sealed class SingletonSample : ISingletonSample, ISingletonService;

internal sealed class ConventionExplicitSample : IExplicitSample, IScopedService;

internal sealed class ExplicitSample : IExplicitSample;

internal sealed class UnmarkedSample : IUnmarkedSample;

internal sealed class SharedSampleA : ISharedSample, IScopedService;

internal sealed class SharedSampleB : ISharedSample, ISingletonService;

/// <summary>
/// Registration rules at descriptor level. Resolution through the real container (<c>IEnumerable&lt;T&gt;</c>,
/// lifetimes) is covered by <c>AgentShield.IntegrationTests.Composition.ConventionalResolutionTests</c>.
/// </summary>
public class ConventionalRegistrationTests
{
    private static readonly System.Reflection.Assembly TestAssembly = typeof(ConventionalRegistrationTests).Assembly;

    [Theory]
    [InlineData(typeof(IScopedSample), typeof(ScopedSample), ServiceLifetime.Scoped)]
    [InlineData(typeof(ITransientSample), typeof(TransientSample), ServiceLifetime.Transient)]
    [InlineData(typeof(ISingletonSample), typeof(SingletonSample), ServiceLifetime.Singleton)]
    public void AddMarkedServices_RegistersMarkedClassesWithMarkerLifetime(Type serviceType, Type implementationType, ServiceLifetime lifetime)
    {
        var services = new ServiceCollection().AddMarkedServices(TestAssembly);

        var descriptor = Assert.Single(services, d => d.ServiceType == serviceType);
        Assert.Equal(implementationType, descriptor.ImplementationType);
        Assert.Equal(lifetime, descriptor.Lifetime);
    }

    [Fact]
    public void AddMarkedServices_DoesNotRegisterMarkerInterfacesOrUnmarkedClasses()
    {
        var services = new ServiceCollection().AddMarkedServices(TestAssembly);

        Assert.DoesNotContain(services, d => d.ServiceType == typeof(IScopedService));
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(ITransientService));
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(ISingletonService));
        Assert.DoesNotContain(services, d => d.ServiceType == typeof(IUnmarkedSample));
    }

    [Fact]
    public void AddMarkedServices_SharedInterface_RegistersEveryImplementationWithItsOwnLifetime()
    {
        var services = new ServiceCollection().AddMarkedServices(TestAssembly);

        var registrations = services
            .Where(d => d.ServiceType == typeof(ISharedSample))
            .Select(d => (d.ImplementationType, d.Lifetime))
            .OrderBy(r => r.ImplementationType!.Name);

        Assert.Equal(
            [(typeof(SharedSampleA), ServiceLifetime.Scoped), (typeof(SharedSampleB), ServiceLifetime.Singleton)],
            registrations);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AddMarkedServices_ExplicitRegistration_StaysLastSoItWinsSingleResolution(bool registerExplicitFirst)
    {
        var services = new ServiceCollection();
        if (registerExplicitFirst)
        {
            services.AddSingleton<IExplicitSample, ExplicitSample>();
        }

        services.AddMarkedServices(TestAssembly);

        if (!registerExplicitFirst)
        {
            services.AddSingleton<IExplicitSample, ExplicitSample>();
        }

        // Microsoft DI resolves the last registration for a single service; IEnumerable<T> gets all of them.
        var implementations = services.Where(d => d.ServiceType == typeof(IExplicitSample)).Select(d => d.ImplementationType);
        Assert.Equal([typeof(ConventionExplicitSample), typeof(ExplicitSample)], implementations);
    }

    [Fact]
    public void AddMarkedServices_ImplementationAlreadyRegisteredExplicitly_IsNotDuplicatedAndKeepsExplicitLifetime()
    {
        var services = new ServiceCollection();
        services.AddTransient<ISharedSample, SharedSampleA>();

        services.AddMarkedServices(TestAssembly);

        var sampleA = Assert.Single(services, d => d.ServiceType == typeof(ISharedSample) && d.ImplementationType == typeof(SharedSampleA));
        Assert.Equal(ServiceLifetime.Transient, sampleA.Lifetime);
        Assert.Contains(services, d => d.ServiceType == typeof(ISharedSample) && d.ImplementationType == typeof(SharedSampleB));
    }

    [Fact]
    public void AddMarkedServices_ScanningTheSameAssemblyTwice_DoesNotDuplicateRegistrations()
    {
        var once = new ServiceCollection().AddMarkedServices(TestAssembly);
        var twice = new ServiceCollection().AddMarkedServices(TestAssembly).AddMarkedServices(TestAssembly);

        Assert.Equal(once.Count, twice.Count);
        Assert.Equal(twice.Count, twice.Select(d => (d.ServiceType, d.ImplementationType)).Distinct().Count());
    }
}
