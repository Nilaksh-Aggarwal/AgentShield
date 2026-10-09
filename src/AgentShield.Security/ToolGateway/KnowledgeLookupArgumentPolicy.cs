using System.Text.Json;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;

namespace AgentShield.Security.ToolGateway;

/// <summary>
/// The argument policy of <c>knowledge.lookup</c>: exactly one member, <c>query</c>, a string of 1–200 characters that is
/// not only whitespace, without control characters and well-formed. Anything else is rejected, and the tool never runs.
/// </summary>
/// <remarks>
/// <para>A small explicit schema, not a policy language. Member names are exact (<c>Query</c> is an unexpected member, not
/// a second spelling), every member other than <c>query</c> is rejected (a tool call cannot smuggle a path, a URL or an
/// option the tool does not define), and <c>null</c>, numbers, arrays and objects are the wrong type. A repeated
/// <c>query</c> is rejected too, although the API's strict JSON already turns duplicate members into a 400.</para>
/// <para>Bounded and side-effect free: it reads at most the members of one object and checks one string. It never throws
/// for bad input and never puts the value in what it returns.</para>
/// </remarks>
internal sealed class KnowledgeLookupArgumentPolicy : IToolArgumentPolicy, ISingletonService
{
    public const string QueryMember = "query";

    public ToolId Tool { get; } = new("knowledge");

    public ActionName Action { get; } = new("lookup");

    public ToolArgumentCheck Check(JsonElement arguments)
    {
        if (arguments.ValueKind != JsonValueKind.Object)
        {
            return ToolArgumentCheck.Reject(ToolArgumentViolation.NotAnObject);
        }

        JsonElement? query = null;
        foreach (var member in arguments.EnumerateObject())
        {
            // A second "query" is as unexpected as any other member: the API rejects duplicates already, but a JsonElement
            // parsed elsewhere may hold them, and "last one wins" would give one object two readings.
            if (!member.NameEquals(QueryMember) || query is not null)
            {
                return ToolArgumentCheck.Reject(ToolArgumentViolation.UnexpectedArgument);
            }

            query = member.Value;
        }

        if (query is not { } value)
        {
            return ToolArgumentCheck.Reject(ToolArgumentViolation.MissingArgument);
        }

        if (value.ValueKind != JsonValueKind.String)
        {
            return ToolArgumentCheck.Reject(ToolArgumentViolation.WrongType);
        }

        if (ReadString(value) is not { } text)
        {
            return ToolArgumentCheck.Reject(ToolArgumentViolation.InvalidText);
        }

        return KnowledgeLookupArguments.Validate(text) is { } violation
            ? ToolArgumentCheck.Reject(violation)
            : ToolArgumentCheck.Accept(new KnowledgeLookupArguments(text));
    }

    /// <summary>The string's value, or <see langword="null"/> when it escapes a lone surrogate, which has no text value.</summary>
    private static string? ReadString(JsonElement value)
    {
        try
        {
            return value.GetString();
        }
        catch (InvalidOperationException)
        {
            return null;
        }
    }
}
