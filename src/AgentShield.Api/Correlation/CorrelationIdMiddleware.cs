using System.Buffers;
using Serilog.Context;

namespace AgentShield.Api.Correlation;

/// <summary>
/// Establishes the request correlation ID: accepts a well-formed inbound <c>X-Correlation-ID</c>,
/// otherwise generates one; stores it on the <see cref="HttpContext"/>, pushes it into the log
/// context and echoes it on the response (including error responses).
/// </summary>
/// <remarks>
/// Inbound values are untrusted: only short IDs made of <c>[A-Za-z0-9._:-]</c> are accepted, which
/// prevents log injection and header abuse. Must be the first middleware in the pipeline.
/// </remarks>
internal sealed class CorrelationIdMiddleware(RequestDelegate next, ILogger<CorrelationIdMiddleware> logger)
{
    public const string HeaderName = "X-Correlation-ID";
    public const int MaxLength = 64;

    private static readonly SearchValues<char> AllowedCharacters =
        SearchValues.Create("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:-");

    public async Task InvokeAsync(HttpContext context)
    {
        var inbound = context.Request.Headers[HeaderName].ToString();
        string correlationId;
        if (IsValid(inbound))
        {
            correlationId = inbound;
        }
        else
        {
            correlationId = Guid.NewGuid().ToString("N");
            if (inbound.Length > 0 && logger.IsEnabled(LogLevel.Debug))
            {
                // Never log the rejected value itself.
                logger.LogDebug("Rejected malformed inbound {HeaderName} header (length {Length}); generated a new one.", HeaderName, inbound.Length);
            }
        }

        context.SetCorrelationId(correlationId);

        // OnStarting runs after the exception handler has cleared the response, so error responses keep the header.
        context.Response.OnStarting(() =>
        {
            context.Response.Headers[HeaderName] = correlationId;
            return Task.CompletedTask;
        });

        using (LogContext.PushProperty("CorrelationId", correlationId))
        {
            await next(context);
        }
    }

    internal static bool IsValid(string? value) =>
        !string.IsNullOrEmpty(value)
        && value.Length <= MaxLength
        && !value.AsSpan().ContainsAnyExcept(AllowedCharacters);
}
