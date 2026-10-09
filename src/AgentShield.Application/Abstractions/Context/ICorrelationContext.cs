namespace AgentShield.Application.Abstractions.Context;

/// <summary>
/// The correlation ID of the operation in progress (for HTTP requests, the <c>X-Correlation-ID</c> value). Lets use
/// cases stamp audit records without depending on the transport.
/// </summary>
public interface ICorrelationContext
{
    string CorrelationId { get; }
}
