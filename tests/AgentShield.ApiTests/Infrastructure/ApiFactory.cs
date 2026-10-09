using AgentShield.ApiTests.Probes;
using FluentValidation;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace AgentShield.ApiTests.Infrastructure;

/// <summary>
/// Hosts the real API pipeline in memory and adds a test-only probe controller, so HTTP contracts
/// (envelope, Problem Details, status codes, validation) are verified without shipping demo endpoints.
/// </summary>
/// <remarks>
/// Clients created by this factory authenticate as <c>test-analyzer</c> (<see cref="TestApiKeys.Analyzer"/>), and rate
/// limits are raised far above what any contract test sends, so contract tests exercise what they always did.
/// Authentication, authorization and rate-limit tests remove the header or configure their own limits.
/// </remarks>
public class ApiFactory : WebApplicationFactory<Program>
{
    public const int GenerousPermitLimit = 100_000;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");
        builder.UseSetting("Serilog:MinimumLevel:Default", "Warning");

        // Security events are the audit trail: outside Development the API refuses to start if the log level hides them,
        // and tests switch this factory to Production.
        builder.UseSetting("Serilog:MinimumLevel:Override:AgentShield.Infrastructure.SecurityEvents", "Information");

        // Never the developer's AI settings or User Secrets: AI off, key blank (contract tests make no provider calls).
        builder.UseSetting("Ai:Enabled", "false");
        builder.UseSetting("Ai:Gemini:ApiKey", "");

        TestApiKeys.Configure(builder);
        builder.UseSetting("RateLimiting:Firewall:PermitLimit", GenerousPermitLimit.ToString(System.Globalization.CultureInfo.InvariantCulture));
        builder.UseSetting("RateLimiting:Standard:PermitLimit", GenerousPermitLimit.ToString(System.Globalization.CultureInfo.InvariantCulture));

        builder.ConfigureTestServices(services =>
        {
            services.AddControllers().AddApplicationPart(typeof(ContractProbeController).Assembly);
            services.AddScoped<IValidator<ProbeRequest>, ProbeRequestValidator>();
        });
    }

    protected override void ConfigureClient(HttpClient client)
    {
        ArgumentNullException.ThrowIfNull(client);
        base.ConfigureClient(client);
        client.DefaultRequestHeaders.Add(TestApiKeys.HeaderName, TestApiKeys.Analyzer);
    }
}
