using AgentShield.Application.Abstractions.Caching;
using AgentShield.Infrastructure.Persistence;
using AgentShield.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AgentShield.IntegrationTests.Composition;

public class CompositionTests(AgentShieldFactory factory) : IClassFixture<AgentShieldFactory>
{
    [Fact]
    public void Host_BuildsWithDependencyValidation()
    {
        // Creating the client builds the host; in Development ValidateOnBuild checks every registration.
        using var client = factory.CreateClient();

        Assert.NotNull(factory.Services.GetRequiredService<ICacheService>());
    }

    [Fact]
    public void CacheService_IsASingleton()
    {
        using var first = factory.Services.CreateScope();
        using var second = factory.Services.CreateScope();

        Assert.Same(
            first.ServiceProvider.GetRequiredService<ICacheService>(),
            second.ServiceProvider.GetRequiredService<ICacheService>());
    }

    [Fact]
    public void DbContext_IsNotRegistered_WhenNoConnectionStringIsConfigured()
    {
        using var scope = factory.Services.CreateScope();

        Assert.Null(scope.ServiceProvider.GetService<AgentShieldDbContext>());
    }

    [Fact]
    public void DbContext_IsRegistered_WhenConnectionStringIsConfigured()
    {
        using var withDatabase = factory.WithWebHostBuilder(builder =>
            builder.UseSetting("ConnectionStrings:AgentShield", "Host=localhost;Database=agentshield;Username=test;Password=test"));
        using var scope = withDatabase.Services.CreateScope();

        Assert.NotNull(scope.ServiceProvider.GetService<AgentShieldDbContext>());
    }

    [Theory]
    [InlineData("Cache:SizeLimit", "0")]
    [InlineData("Cache:DefaultExpiration", "00:00:00")]
    [InlineData("Database:CommandTimeoutSeconds", "0")]
    [InlineData("Api:MaxRequestBodySizeBytes", "-1")]
    public void InvalidConfiguration_FailsAtStartup(string key, string value)
    {
        using var misconfigured = factory.WithWebHostBuilder(builder => builder.UseSetting(key, value));

        var exception = Assert.ThrowsAny<Exception>(() => misconfigured.CreateClient());

        Assert.Contains(SelfAndInner(exception), candidate => candidate is OptionsValidationException);
    }

    private static IEnumerable<Exception> SelfAndInner(Exception exception)
    {
        yield return exception;
        IEnumerable<Exception> inner = exception is AggregateException aggregate
            ? aggregate.InnerExceptions
            : exception.InnerException is null ? [] : [exception.InnerException];
        foreach (var descendant in inner.SelectMany(SelfAndInner))
        {
            yield return descendant;
        }
    }
}
