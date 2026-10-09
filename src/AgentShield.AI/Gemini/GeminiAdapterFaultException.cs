using System.Runtime.ExceptionServices;
using System.Text;

namespace AgentShield.AI.Gemini;

/// <summary>
/// An unexpected fault in the Gemini SDK call, in place of the original exception. The original message is dropped
/// because it can carry text the provider chose (its error body, a member name, a charset, a value .NET quotes in a
/// <see cref="FormatException"/>). The type names of the exception and its inner exceptions, and the original stack
/// trace, are kept for diagnosis. The analysis still fails closed (500).
/// </summary>
public sealed class GeminiAdapterFaultException : Exception
{
    private const int MaxInnerExceptions = 8;

    public GeminiAdapterFaultException()
    {
    }

    public GeminiAdapterFaultException(string message)
        : base(message)
    {
    }

    public GeminiAdapterFaultException(string message, Exception innerException)
        : base(message, innerException)
    {
    }

    /// <summary>The replacement for <paramref name="original"/>: its type names and stack trace, never its messages.</summary>
    internal static GeminiAdapterFaultException From(Exception original)
    {
        ArgumentNullException.ThrowIfNull(original);

        var types = new StringBuilder(original.GetType().FullName);
        var inner = original.InnerException;
        for (var count = 0; inner is not null && count < MaxInnerExceptions; count++, inner = inner.InnerException)
        {
            types.Append(" <- ").Append(inner.GetType().FullName);
        }

        var fault = new GeminiAdapterFaultException(
            $"The Gemini SDK call failed unexpectedly ({types}). The original message is not kept: it can carry provider-controlled text.");
        return original.StackTrace is { } stackTrace
            ? (GeminiAdapterFaultException)ExceptionDispatchInfo.SetRemoteStackTrace(fault, stackTrace)
            : fault;
    }
}
