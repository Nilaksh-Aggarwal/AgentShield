namespace AgentShield.Api.Correlation;

public static class CorrelationIdHttpContextExtensions
{
    private static readonly object ItemKey = new();

    /// <summary>
    /// The correlation ID of the current request. Falls back to <see cref="HttpContext.TraceIdentifier"/>
    /// if the correlation middleware has not run (it always should).
    /// </summary>
    public static string GetCorrelationId(this HttpContext context)
    {
        ArgumentNullException.ThrowIfNull(context);
        return context.Items.TryGetValue(ItemKey, out var value) && value is string correlationId
            ? correlationId
            : context.TraceIdentifier;
    }

    internal static void SetCorrelationId(this HttpContext context, string correlationId) =>
        context.Items[ItemKey] = correlationId;
}
