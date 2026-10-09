using Serilog.Core;
using Serilog.Events;

namespace AgentShield.Api.Logging;

/// <summary>
/// Removes <c>RequestPath</c>, which ASP.NET Core's per-request log scope adds to every event of a request. The caller
/// chooses the path, also without a key, so it could carry a key, attack text or a forged log line. Events keep
/// <c>CorrelationId</c> and <c>RequestId</c>, and the request log records the matched route template instead
/// (<c>Endpoint</c>).
/// </summary>
internal sealed class RequestPathRemovalEnricher : ILogEventEnricher
{
    public const string PropertyName = "RequestPath";

    public void Enrich(LogEvent logEvent, ILogEventPropertyFactory propertyFactory)
    {
        ArgumentNullException.ThrowIfNull(logEvent);
        logEvent.RemovePropertyIfPresent(PropertyName);
    }
}
