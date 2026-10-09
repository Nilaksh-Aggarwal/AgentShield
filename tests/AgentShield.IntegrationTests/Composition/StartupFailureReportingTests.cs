using AgentShield.IntegrationTests.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace AgentShield.IntegrationTests.Composition;

/// <summary>
/// X-05 (Milestone 13): a startup that fails validation is reported as that validation failure, whichever thread gets
/// there first. The application's entry point starts the host itself; when it used <c>RunAsync</c>, a failed start disposed
/// the host, and a test host attaching to it a moment later (under load) saw an <see cref="ObjectDisposedException"/>
/// instead. These tests force the late attach that load produced, so the race is checked deterministically.
/// </summary>
public sealed class StartupFailureReportingTests
{
    public static TheoryData<string, string, int> InvalidSettings => new()
    {
        { "Ai:Model", "gemini-3.8-flash?key=x", 0 },
        { "Ai:Model", "gemini-3.8-flash?key=x", 1_000 },
        { "Cors:AllowedOrigins:0", "console.example", 1_000 },
        { "Ai:TimeoutSeconds", "4", 1_000 },
    };

    [Theory]
    [MemberData(nameof(InvalidSettings))]
    public void InvalidConfiguration_IsReportedAsTheValidationFailure_EvenWhenTheTestHostAttachesLate(string key, string value, int attachDelayMs)
    {
        using var factory = new LateAttachingFactory(key, value, attachDelayMs);

        var exception = Assert.ThrowsAny<Exception>(() => factory.CreateClient());

        Assert.True(Chain(exception).OfType<OptionsValidationException>().Any(), $"Expected an options validation failure, got: {Describe(exception)}");
        Assert.DoesNotContain(Chain(exception), candidate => candidate is ObjectDisposedException);
    }

    private static IEnumerable<Exception> Chain(Exception exception)
    {
        yield return exception;
        IEnumerable<Exception> inner = exception is AggregateException aggregate
            ? aggregate.InnerExceptions
            : exception.InnerException is null ? [] : [exception.InnerException];
        foreach (var descendant in inner.SelectMany(Chain))
        {
            yield return descendant;
        }
    }

    // Types only: a configuration failure's message can name settings, and the assertion text ends up in test logs.
    private static string Describe(Exception exception) => string.Join(" > ", Chain(exception).Select(candidate => candidate.GetType().Name));

    private sealed class LateAttachingFactory(string key, string value, int attachDelayMs) : AgentShieldFactory
    {
        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            base.ConfigureWebHost(builder);
            builder.UseSetting(key, value);
        }

        protected override IHost CreateHost(IHostBuilder builder)
        {
            var host = builder.Build();

            // The order load produced: the entry point fails its start before the test host attaches.
            Thread.Sleep(attachDelayMs);
            host.Start();
            return host;
        }
    }
}
