using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Hosting;

namespace AgentShield.IntegrationTests.Infrastructure;

/// <summary>API keys of the test clients. Hashes are computed here independently of the API's own hashing code.</summary>
public static class TestApiKeys
{
    public const string HeaderName = "X-API-Key";

    /// <summary>Client <c>test-analyzer</c>: holds <c>firewall:analyze</c>. Sent by every factory client by default.</summary>
    public const string Analyzer = "test-analyzer-key-0123456789abcdefghijklmnop";

    public const string AnalyzerClientId = "test-analyzer";

    public static string Hash(string key) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key)));

    public static void Configure(IWebHostBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.UseSetting($"Authentication:Clients:{AnalyzerClientId}:KeyHashes:0", Hash(Analyzer));
        builder.UseSetting($"Authentication:Clients:{AnalyzerClientId}:Permissions:0", "firewall:analyze");
    }
}
