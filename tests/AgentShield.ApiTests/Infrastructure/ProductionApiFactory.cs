using Microsoft.AspNetCore.Hosting;

namespace AgentShield.ApiTests.Infrastructure;

/// <summary>
/// The API in the Production environment: appsettings.json only (no Development client, no Development CORS origin, no
/// User Secrets), plus the test clients and, unless disabled, one configured production origin.
/// </summary>
public sealed class ProductionApiFactory(bool configureOrigin = true) : ApiFactory
{
    public const string AllowedOrigin = "https://console.agentshield.example";

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        base.ConfigureWebHost(builder);
        builder.UseEnvironment("Production");
        if (configureOrigin)
        {
            builder.UseSetting("Cors:AllowedOrigins:0", AllowedOrigin);
        }
    }
}
