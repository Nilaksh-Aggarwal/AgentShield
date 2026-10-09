namespace AgentShield.Api.Http.Responses;

/// <summary>
/// Envelope for every successful JSON response body under <c>/api</c>.
/// </summary>
/// <remarks>
/// There is intentionally no <c>success</c> flag: the HTTP status code conveys the outcome and
/// failures are always RFC 9457 Problem Details, never this envelope.
/// </remarks>
public sealed record ApiResponse<T>(T Data, ApiResponseMeta Meta);

/// <param name="CorrelationId">Value of the <c>X-Correlation-ID</c> response header.</param>
/// <param name="Timestamp">Server time (UTC) at which the response was produced.</param>
public sealed record ApiResponseMeta(string CorrelationId, DateTimeOffset Timestamp);
