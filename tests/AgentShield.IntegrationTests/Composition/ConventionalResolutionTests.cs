using AgentShield.Application.Abstractions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;

namespace AgentShield.IntegrationTests.Composition;

public interface ITestService;

internal sealed class TestServiceA : ITestService, IScopedService;

internal sealed class TestServiceB : ITestService, IScopedService;

// Shape of the future firewall: several detectors behind one interface, resolved as IEnumerable<IThreatDetector>.
public interface IThreatDetector;

internal sealed class DetectorA : IThreatDetector, ISingletonService;

internal sealed class DetectorB : IThreatDetector, IScopedService;

// Unmarked: stands for a detector that needs configuration and is therefore registered explicitly.
internal sealed class ConfiguredDetector : IThreatDetector;

/// <summary>
/// Convention registrations resolved through the real Microsoft DI container, as the host builds it
/// (scope and build-time validation on).
/// </summary>
public class ConventionalResolutionTests
{
    private static readonly System.Reflection.Assembly TestAssembly = typeof(ConventionalResolutionTests).Assembly;

    [Fact]
    public void AddMarkedServices_SeveralImplementations_AllResolveThroughEnumerable()
    {
        using var provider = Build(new ServiceCollection().AddMarkedServices(TestAssembly));
        using var scope = provider.CreateScope();

        var resolved = scope.ServiceProvider.GetServices<ITestService>().Select(s => s.GetType());

        Assert.Equal([typeof(TestServiceA), typeof(TestServiceB)], resolved.OrderBy(t => t.Name));
    }

    [Fact]
    public void AddMarkedServices_ThreatDetectorsWithDifferentLifetimes_AllResolveOnceEach()
    {
        using var provider = Build(new ServiceCollection().AddMarkedServices(TestAssembly));
        using var first = provider.CreateScope();
        using var second = provider.CreateScope();

        var firstDetectors = first.ServiceProvider.GetServices<IThreatDetector>().ToArray();
        var secondDetectors = second.ServiceProvider.GetServices<IThreatDetector>().ToArray();

        Assert.Equal([typeof(DetectorA), typeof(DetectorB)], firstDetectors.Select(d => d.GetType()).OrderBy(t => t.Name));
        Assert.Same(firstDetectors.OfType<DetectorA>().Single(), secondDetectors.OfType<DetectorA>().Single());
        Assert.NotSame(firstDetectors.OfType<DetectorB>().Single(), secondDetectors.OfType<DetectorB>().Single());
    }

    [Fact]
    public void AddMarkedServices_ExplicitlyRegisteredDetector_DoesNotHideConventionDetectors()
    {
        // Under a skip-by-service-type strategy this explicit registration silently dropped DetectorA and DetectorB.
        var services = new ServiceCollection();
        services.AddSingleton<IThreatDetector, ConfiguredDetector>();

        using var provider = Build(services.AddMarkedServices(TestAssembly));
        using var scope = provider.CreateScope();

        var resolved = scope.ServiceProvider.GetServices<IThreatDetector>().Select(d => d.GetType());

        Assert.Equal([typeof(ConfiguredDetector), typeof(DetectorA), typeof(DetectorB)], resolved.OrderBy(t => t.Name));
        Assert.IsType<ConfiguredDetector>(scope.ServiceProvider.GetRequiredService<IThreatDetector>());
    }

    private static ServiceProvider Build(IServiceCollection services) =>
        services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true, ValidateOnBuild = true });
}
