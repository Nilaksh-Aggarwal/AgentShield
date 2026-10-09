using System.Globalization;
using System.Net;
using AgentShield.ApiTests.Infrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace AgentShield.ApiTests.RateLimiting;

/// <summary>
/// Per-client fixed windows through the real pipeline. Each test builds its own host (own in-memory limiter) with small
/// limits and a 60 s window, so a window never rolls over during a test and the outcome is deterministic (except
/// <c>Window_RefillsOnceItEnds_SoALimitedClientIsServedAgain</c>, which lets a 1 s window end on purpose).
/// </summary>
public sealed class RateLimitingTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    [Fact]
    public async Task Firewall_BelowAndExactlyAtLimit_Succeeds_OverLimit_Returns429()
    {
        using var host = WithLimits(firewall: 3);
        using var client = host.CreateClient();

        var statuses = new List<HttpStatusCode>();
        for (var request = 0; request < 4; request++)
        {
            statuses.Add((await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer))).StatusCode);
        }

        Assert.Equal([HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.TooManyRequests], statuses);
    }

    [Fact]
    public async Task OverLimit_Returns429ProblemDetails_WithRetryAfter_AndWithoutLimiterDetails()
    {
        using var host = WithLimits(firewall: 1);
        using var client = host.CreateClient();
        await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));

        var response = await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.TooManyRequests, "Request.RateLimited");
        Assert.Equal("https://tools.ietf.org/html/rfc6585#section-4", problem.GetProperty("type").GetString());
        var retryAfter = int.Parse(Assert.Single(response.Headers.GetValues("Retry-After")), NumberStyles.None, CultureInfo.InvariantCulture);
        Assert.InRange(retryAfter, 1, 60);
        var body = problem.GetRawText();
        // Ordinal: the instance member legitimately holds the path "/api/v1/firewall/analyze".
        foreach (var internalTerm in new[] { "Firewall", "Standard", "client:", "PermitLimit", "Window", "test-analyzer" })
        {
            Assert.DoesNotContain(internalTerm, body, StringComparison.Ordinal);
        }
    }

    [Fact]
    public async Task OverLimit_RetryAfter_IsTheTimeLeftInTheWindow_NotAPlaceholder()
    {
        // Right after a fresh 60 s window is used up, nearly all of it is left (mutation testing: a Retry-After of 1 passed
        // the range check above).
        using var host = WithLimits(firewall: 1);
        using var client = host.CreateClient();
        await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));

        var response = await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.InRange(int.Parse(Assert.Single(response.Headers.GetValues("Retry-After")), NumberStyles.None, CultureInfo.InvariantCulture), 45, 60);
    }

    [Fact]
    public async Task Window_RefillsOnceItEnds_SoALimitedClientIsServedAgain()
    {
        // The only test that lets a window end: 1 s is the shortest window the options allow, and the limiter's own timer
        // refills it (mutation testing: a limiter that never refilled went unnoticed).
        using var host = WithLimits(firewall: 1, settings: ("RateLimiting:Firewall:WindowSeconds", "1"));
        using var client = host.CreateClient();
        var first = await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));
        var second = await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));

        await Task.Delay(TimeSpan.FromSeconds(2));
        var later = await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));

        Assert.Equal([HttpStatusCode.OK, HttpStatusCode.TooManyRequests, HttpStatusCode.OK], [first.StatusCode, second.StatusCode, later.StatusCode]);
    }

    [Fact]
    public void Options_LeftUnconfigured_KeepRateLimitingOn()
    {
        // The secure default: configuration that omits RateLimiting:Enabled does not switch rate limiting off.
        Assert.True(new AgentShield.Api.RateLimiting.RateLimitingOptions().Enabled);
    }

    [Fact]
    public async Task Limits_ArePerClient()
    {
        using var host = WithLimits(firewall: 2);
        using var client = AnalyzeRequests.CreateAnonymousClient(host);
        for (var request = 0; request < 3; request++)
        {
            await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));
        }

        var exhausted = await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));
        var other = await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.SecondAnalyzer));

        Assert.Equal(HttpStatusCode.TooManyRequests, exhausted.StatusCode);
        Assert.Equal(HttpStatusCode.OK, other.StatusCode);
    }

    [Fact]
    public async Task FirewallPolicy_IsStricterThanStandard_AndOverridesTheControllerDefault()
    {
        using var host = WithLimits(firewall: 2, standard: 1_000);
        using var client = host.CreateClient();
        for (var request = 0; request < 2; request++)
        {
            await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));
        }

        var firewall = await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));
        var standardEndpoint = await client.GetAsync("/api/v1/__probe/ok");

        Assert.Equal(HttpStatusCode.TooManyRequests, firewall.StatusCode);
        Assert.Equal(HttpStatusCode.OK, standardEndpoint.StatusCode);
    }

    [Fact]
    public async Task Activity_IsLimitedPerClientByTheStandardPolicy_With429AndRetryAfter()
    {
        using var host = WithLimits(firewall: 1_000, standard: 2);
        using var client = AnalyzeRequests.CreateAnonymousClient(host);
        for (var request = 0; request < 2; request++)
        {
            Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(ActivityRequest())).StatusCode);
        }

        var limited = await client.SendAsync(ActivityRequest());
        var firewall = await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));

        await ProblemAssertions.AssertProblemAsync(limited, HttpStatusCode.TooManyRequests, "Request.RateLimited");
        Assert.True(limited.Headers.RetryAfter?.Delta > TimeSpan.Zero);
        Assert.Equal(HttpStatusCode.OK, firewall.StatusCode);

        static HttpRequestMessage ActivityRequest()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/activity");
            request.Headers.Add(TestApiKeys.HeaderName, TestApiKeys.ActivityReader);
            return request;
        }
    }

    [Fact]
    public async Task AgentAuthorization_IsLimitedPerClientByTheStandardPolicy_With429AndRetryAfter()
    {
        using var host = WithLimits(firewall: 1_000, standard: 2);
        const string Body = """{"agentId":"support-agent","tool":"data","action":"read","capability":"data:read"}""";
        for (var request = 0; request < 2; request++)
        {
            Assert.Equal(HttpStatusCode.OK, (await AgentRequests.SendAsync(host, Body)).StatusCode);
        }

        var limited = await AgentRequests.SendAsync(host, Body);
        var otherRuntime = await AgentRequests.SendAsync(host, Body, TestApiKeys.OtherRuntime);

        await ProblemAssertions.AssertProblemAsync(limited, HttpStatusCode.TooManyRequests, "Request.RateLimited");
        Assert.True(limited.Headers.RetryAfter?.Delta > TimeSpan.Zero);
        Assert.DoesNotContain("decision", await limited.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(HttpStatusCode.OK, otherRuntime.StatusCode);
    }

    [Fact]
    public async Task ToolGateway_IsLimitedPerClientByTheStandardPolicy_With429AndRetryAfter_AndALimitedCallRunsNothing()
    {
        using var host = factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("RateLimiting:Standard:PermitLimit", "2");
            builder.UseSetting("RateLimiting:Standard:WindowSeconds", "60");
            GatewayApiFactory.Configure(builder);
            builder.ConfigureTestServices(GatewayApiFactory.ProbeEveryTool);
        });
        var probe = host.Services.GetRequiredService<ToolProbe>();
        var body = GatewayRequests.Lookup("rate limiting");
        for (var request = 0; request < 2; request++)
        {
            Assert.Equal(HttpStatusCode.OK, (await GatewayRequests.SendAsync(host, body)).StatusCode);
        }

        var limited = await GatewayRequests.SendAsync(host, body);
        var otherAgent = await GatewayRequests.SendAsync(host, body, GatewayApiFactory.ReaderKey);

        await ProblemAssertions.AssertProblemAsync(limited, HttpStatusCode.TooManyRequests, "Request.RateLimited");
        Assert.True(limited.Headers.RetryAfter?.Delta > TimeSpan.Zero);
        Assert.DoesNotContain("executed", await limited.Content.ReadAsStringAsync(), StringComparison.OrdinalIgnoreCase);
        Assert.Equal(HttpStatusCode.OK, otherAgent.StatusCode);
        Assert.Equal(2, probe.Count);
    }

    [Fact]
    public async Task StandardPolicy_AppliesToEndpointsWithoutOwnPolicy()
    {
        using var host = WithLimits(firewall: 1_000, standard: 2);
        using var client = host.CreateClient();
        await client.GetAsync("/api/v1/__probe/ok");
        await client.GetAsync("/api/v1/__probe/ok");

        var probe = await client.GetAsync("/api/v1/__probe/ok");
        var firewall = await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));

        await ProblemAssertions.AssertProblemAsync(probe, HttpStatusCode.TooManyRequests, "Request.RateLimited");
        Assert.Equal(HttpStatusCode.OK, firewall.StatusCode);
    }

    [Fact]
    public async Task Liveness_IsNeverRateLimited_WhileReadinessIs()
    {
        using var host = WithLimits(standard: 1);
        using var client = AnalyzeRequests.CreateAnonymousClient(host);

        for (var request = 0; request < 30; request++)
        {
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/live")).StatusCode);
        }

        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/ready")).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.GetAsync("/health/ready")).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/health/live")).StatusCode);
    }

    [Fact]
    public async Task AnonymousRequests_ArePartitionedByRemoteAddress_NotPooled()
    {
        // Readiness is the only anonymous endpoint with a limit. Each address has its own budget, so one caller cannot
        // use up everybody else's probes (mutation testing: pooling every anonymous request went unnoticed). The test
        // server has no remote address, so a test-only middleware sets it.
        using var host = WithLimits(standard: 1).WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services => services.AddTransient<IStartupFilter, RemoteAddressFromTestHeader>()));
        using var client = AnalyzeRequests.CreateAnonymousClient(host);

        var first = await GetReadinessAsync(client, "192.0.2.1");
        var again = await GetReadinessAsync(client, "192.0.2.1");
        var otherAddress = await GetReadinessAsync(client, "192.0.2.2");

        Assert.Equal([HttpStatusCode.OK, HttpStatusCode.TooManyRequests, HttpStatusCode.OK], [first, again, otherAddress]);
    }

    [Fact]
    public async Task UnauthenticatedAndForbiddenRequests_DoNotConsumeTheClientsBudget()
    {
        using var host = WithLimits(firewall: 2);
        using var client = AnalyzeRequests.CreateAnonymousClient(host);
        for (var request = 0; request < 5; request++)
        {
            Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(AnalyzeRequests.Create())).StatusCode);
            Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.NoPermissions))).StatusCode);
        }

        var first = await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));
        var second = await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer));

        Assert.Equal(HttpStatusCode.OK, first.StatusCode);
        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
    }

    [Fact]
    public async Task ConcurrentFlood_AdmitsExactlyThePermitLimit()
    {
        const int limit = 5;
        const int requests = 40;
        using var host = WithLimits(firewall: limit);
        using var client = host.CreateClient();

        var responses = await Task.WhenAll(Enumerable.Range(0, requests)
            .Select(_ => client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer))));

        Assert.Equal(limit, responses.Count(response => response.StatusCode == HttpStatusCode.OK));
        Assert.Equal(requests - limit, responses.Count(response => response.StatusCode == HttpStatusCode.TooManyRequests));
    }

    [Fact]
    public async Task Disabled_InDevelopment_AdmitsEveryRequest()
    {
        using var host = WithLimits(firewall: 1, settings: ("RateLimiting:Enabled", "false"));
        using var client = host.CreateClient();

        for (var request = 0; request < 5; request++)
        {
            Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(AnalyzeRequests.Create(apiKeys: TestApiKeys.Analyzer))).StatusCode);
        }
    }

    private static async Task<HttpStatusCode> GetReadinessAsync(HttpClient client, string remoteAddress)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/health/ready");
        request.Headers.Add(RemoteAddressFromTestHeader.HeaderName, remoteAddress);
        using var response = await client.SendAsync(request);
        return response.StatusCode;
    }

    /// <summary>Test only: sets the connection's remote address from a header, before anything else in the pipeline.</summary>
    private sealed class RemoteAddressFromTestHeader : IStartupFilter
    {
        public const string HeaderName = "X-Test-Remote-Address";

        public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
        {
            app.Use((context, nextMiddleware) =>
            {
                if (IPAddress.TryParse(context.Request.Headers[HeaderName].ToString(), out var address))
                {
                    context.Connection.RemoteIpAddress = address;
                }

                return nextMiddleware(context);
            });
            next(app);
        };
    }

    private WebApplicationFactory<Program> WithLimits(int firewall = 1_000, int standard = 1_000, params (string Key, string Value)[] settings) =>
        factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("RateLimiting:Firewall:PermitLimit", firewall.ToString(CultureInfo.InvariantCulture));
            builder.UseSetting("RateLimiting:Firewall:WindowSeconds", "60");
            builder.UseSetting("RateLimiting:Standard:PermitLimit", standard.ToString(CultureInfo.InvariantCulture));
            builder.UseSetting("RateLimiting:Standard:WindowSeconds", "60");
            foreach (var (key, value) in settings)
            {
                builder.UseSetting(key, value);
            }
        });
}
