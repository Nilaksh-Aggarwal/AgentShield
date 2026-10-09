using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Hosting;

namespace AgentShield.ApiTests.Infrastructure;

/// <summary>API keys of the test clients. Hashes are computed here independently of the API's own hashing code.</summary>
public static class TestApiKeys
{
    public const string HeaderName = "X-API-Key";

    /// <summary>Client <c>test-analyzer</c>: holds <c>firewall:analyze</c>. Sent by every factory client by default.</summary>
    public const string Analyzer = "test-analyzer-key-0123456789abcdefghijklmnop";

    /// <summary>Client <c>test-no-permissions</c>: authenticated, allowed nothing.</summary>
    public const string NoPermissions = "test-no-permissions-key-0123456789abcdefghij";

    /// <summary>A second client with <c>firewall:analyze</c>, for per-client rate-limit tests.</summary>
    public const string SecondAnalyzer = "test-second-analyzer-key-0123456789abcdefgh";

    /// <summary>Client <c>test-activity-reader</c>: holds <c>activity:read</c> only (an operator console).</summary>
    public const string ActivityReader = "test-activity-reader-key-0123456789abcdefgh";

    /// <summary>Client <c>test-agent-runtime</c>: holds <c>agent:authorize</c> only; the runtime the test agents are bound to.</summary>
    public const string AgentRuntime = "test-agent-runtime-key-0123456789abcdefghij";

    public const string AgentRuntimeClientId = "test-agent-runtime";

    /// <summary>Client <c>test-other-runtime</c>: holds <c>agent:authorize</c>, but no test agent is bound to it.</summary>
    public const string OtherRuntime = "test-other-runtime-key-0123456789abcdefghij";

    /// <summary>Client <c>test-approver</c>: holds <c>agent:approve</c> only (a person's console deciding held tool calls).</summary>
    public const string Approver = "test-approver-key-0123456789abcdefghijklmnop";

    public const string ApproverClientId = "test-approver";

    /// <summary>The public Development key (appsettings.Development.json).</summary>
    public const string Development = "agentshield-development-only-key-not-a-secret";

    public static string Hash(string key) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(key)));

    /// <summary>Registers the test clients on a host.</summary>
    public static void Configure(IWebHostBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        builder.UseSetting("Authentication:Clients:test-analyzer:KeyHashes:0", Hash(Analyzer));
        builder.UseSetting("Authentication:Clients:test-analyzer:Permissions:0", "firewall:analyze");
        builder.UseSetting("Authentication:Clients:test-second-analyzer:KeyHashes:0", Hash(SecondAnalyzer));
        builder.UseSetting("Authentication:Clients:test-second-analyzer:Permissions:0", "firewall:analyze");
        builder.UseSetting("Authentication:Clients:test-no-permissions:KeyHashes:0", Hash(NoPermissions));
        builder.UseSetting("Authentication:Clients:test-activity-reader:KeyHashes:0", Hash(ActivityReader));
        builder.UseSetting("Authentication:Clients:test-activity-reader:Permissions:0", "activity:read");
        builder.UseSetting($"Authentication:Clients:{AgentRuntimeClientId}:KeyHashes:0", Hash(AgentRuntime));
        builder.UseSetting($"Authentication:Clients:{AgentRuntimeClientId}:Permissions:0", "agent:authorize");
        builder.UseSetting("Authentication:Clients:test-other-runtime:KeyHashes:0", Hash(OtherRuntime));
        builder.UseSetting("Authentication:Clients:test-other-runtime:Permissions:0", "agent:authorize");
        builder.UseSetting($"Authentication:Clients:{ApproverClientId}:KeyHashes:0", Hash(Approver));
        builder.UseSetting($"Authentication:Clients:{ApproverClientId}:Permissions:0", "agent:approve");
    }
}
