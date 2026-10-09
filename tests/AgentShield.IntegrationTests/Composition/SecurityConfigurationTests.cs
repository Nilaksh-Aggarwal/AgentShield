using System.Globalization;
using AgentShield.Api.RateLimiting;
using AgentShield.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Options;

namespace AgentShield.IntegrationTests.Composition;

/// <summary>
/// Unsafe or ambiguous security configuration stops the application at startup instead of weakening it silently.
/// </summary>
public class SecurityConfigurationTests(AgentShieldFactory factory) : IClassFixture<AgentShieldFactory>
{
    private const string DevelopmentKeyHash = "a6fe8444310e70027e4344a24208dd445e74f38c4d0ccff50aa3edffae3b59cc";

    [Theory]
    [InlineData("Authentication:Clients:bad-hash:KeyHashes:0", "not-a-sha256-hash")]
    [InlineData("Authentication:Clients:short-hash:KeyHashes:0", "abcdef")]
    [InlineData("Authentication:Clients:Upper-Case:KeyHashes:0", "0000000000000000000000000000000000000000000000000000000000000001")]
    [InlineData("Authentication:Clients::KeyHashes:0", "0000000000000000000000000000000000000000000000000000000000000002")] // empty client ID (Authentication__Clients____KeyHashes__0)
    [InlineData("Authentication:Clients:no-keys:Permissions:0", "firewall:analyze")]
    [InlineData("Authentication:Clients:test-analyzer:Permissions:1", "firewall:admin")]
    [InlineData("RateLimiting:Firewall:PermitLimit", "0")]
    [InlineData("RateLimiting:Firewall:WindowSeconds", "0")]
    [InlineData("RateLimiting:Standard:QueueLimit", "-1")]
    [InlineData("RateLimiting:Standard:WindowSeconds", "86400")]
    [InlineData("Cors:AllowedOrigins:0", "*")]
    [InlineData("Cors:AllowedOrigins:0", "https://console.example/app")]
    [InlineData("Cors:AllowedOrigins:0", "https://console.example/")]
    [InlineData("Cors:AllowedOrigins:0", "https://user@console.example")]
    [InlineData("Cors:AllowedOrigins:0", "console.example")]
    [InlineData("Cors:AllowedOrigins:0", "ftp://console.example")]
    public void InvalidSecurityConfiguration_FailsAtStartup(string key, string value)
    {
        using var misconfigured = factory.WithWebHostBuilder(builder => builder.UseSetting(key, value));

        // The message names the section ("Authentication:Clients", "RateLimiting:Firewall", ...) and never repeats a long
        // configured value such as a hash (mutation testing: emptied messages went unnoticed).
        AssertFailsValidation(misconfigured, namedSetting: string.Join(':', key.Split(':').Take(2)), neverShown: value.Length >= 16 ? value : null);
    }

    [Theory]
    [InlineData(64, true)]
    [InlineData(65, false)]
    public void ClientIdLength_IsLimitedTo64Characters_Inclusive(int length, bool starts)
    {
        var clientId = new string('c', length);
        using var host = factory.WithWebHostBuilder(builder =>
            builder.UseSetting($"Authentication:Clients:{clientId}:KeyHashes:0", TestApiKeys.Hash("client-id-length-test-key-0123456789abcdef")));

        if (starts)
        {
            using var client = host.CreateClient();
            Assert.NotNull(client);
        }
        else
        {
            AssertFailsValidation(host, namedSetting: "Authentication:Clients", neverShown: clientId);
        }
    }

    [Theory]
    [InlineData("RateLimiting:Firewall:PermitLimit", RateLimitingOptions.MaxPermitLimit)]
    [InlineData("RateLimiting:Standard:WindowSeconds", RateLimitingOptions.MaxWindowSeconds)]
    [InlineData("RateLimiting:Standard:QueueLimit", RateLimitingOptions.MaxQueueLimit)]
    public void RateLimitSettings_ExactlyAtTheirMaximum_AreAccepted(string key, int maximum)
    {
        // The maximums are inclusive; the rejection rows above are past them (mutation testing: the bounds were unpinned).
        using var host = factory.WithWebHostBuilder(builder => builder.UseSetting(key, maximum.ToString(CultureInfo.InvariantCulture)));

        using var client = host.CreateClient();

        Assert.NotNull(client);
    }

    [Fact]
    public void SameKeyHashForTwoClients_FailsAtStartup()
    {
        var hash = TestApiKeys.Hash(TestApiKeys.Analyzer);
        using var misconfigured = factory.WithWebHostBuilder(builder =>
            builder.UseSetting("Authentication:Clients:impostor:KeyHashes:0", hash));

        // Reported on whichever of the two clients is read second.
        AssertFailsValidation(misconfigured, namedSetting: "Authentication:Clients:", neverShown: hash);
    }

    [Fact]
    public void DevelopmentKey_OutsideDevelopment_FailsAtStartup()
    {
        using var production = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Authentication:Clients:leaked-development:KeyHashes:0", DevelopmentKeyHash);
        });

        AssertFailsValidation(production, namedSetting: "Authentication:Clients:leaked-development", neverShown: DevelopmentKeyHash);
    }

    [Fact]
    public void RateLimitingDisabled_OutsideDevelopment_FailsAtStartup()
    {
        using var production = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("RateLimiting:Enabled", "false");
        });

        AssertFailsValidation(production, namedSetting: "RateLimiting:Enabled");
    }

    [Fact]
    public void HttpOrigin_OutsideDevelopment_FailsAtStartup()
    {
        using var production = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Cors:AllowedOrigins:0", "http://console.example");
        });

        AssertFailsValidation(production);
    }

    [Theory]
    [InlineData("Serilog:MinimumLevel:Default")]
    [InlineData("Serilog:MinimumLevel:Override:AgentShield")]
    [InlineData("Serilog:MinimumLevel:Override:AgentShield.Infrastructure.SecurityEvents")]
    public void SecurityEventsHiddenByTheLogLevel_OutsideDevelopment_FailsAtStartup(string levelSetting)
    {
        // H-07: security events are the audit trail, and Allow is logged at Information. A level that hides them would let
        // the API decide without leaving any record.
        using var production = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Cors:AllowedOrigins:0", "https://console.example");
            builder.UseSetting(levelSetting, "Warning");
        });

        AssertFailsValidation(production);
    }

    [Fact]
    public void SecurityEventsHiddenByTheLogLevel_InDevelopment_StartsWithAWarning()
    {
        using var development = factory.WithWebHostBuilder(builder =>
            builder.UseSetting("Serilog:MinimumLevel:Override:AgentShield.Infrastructure.SecurityEvents", "Warning"));

        using var client = development.CreateClient();

        Assert.Contains(factory.LogSink.Events, entry =>
            entry.Level == Serilog.Events.LogEventLevel.Warning
            && entry.MessageTemplate.Text.Contains("security events", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ProductionWithHttpsOriginAndNoDevelopmentKey_Starts()
    {
        using var production = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("Cors:AllowedOrigins:0", "https://console.example");
        });

        using var client = production.CreateClient();

        Assert.NotNull(client);
    }

    private static void AssertFailsValidation(
        Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program> host, string? namedSetting = null, string? neverShown = null)
    {
        var exception = Assert.ThrowsAny<Exception>(() => host.CreateClient());

        // On failure, report the whole chain (types and messages; validation messages name settings, never values).
        var chain = SelfAndInner(exception).ToList();
        var description = "Exception chain: " + string.Join(" <- ", chain.Select(candidate => $"{candidate.GetType().Name}: {candidate.Message}"));
        var validation = chain.OfType<OptionsValidationException>().ToList();
        Assert.True(validation.Count > 0, description);
        if (namedSetting is not null)
        {
            Assert.True(validation.Any(candidate => candidate.Message.Contains(namedSetting, StringComparison.Ordinal)), description);
        }

        if (neverShown is not null)
        {
            Assert.DoesNotContain(chain, candidate => candidate.Message.Contains(neverShown, StringComparison.OrdinalIgnoreCase));
        }
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
