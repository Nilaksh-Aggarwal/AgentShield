using System.Collections.Frozen;
using System.Text;
using AgentShield.Application.Abstractions.Agents;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.Agents;
using AgentShield.Domain.Agents.Tools;

namespace AgentShield.Infrastructure.Tools;

/// <summary>
/// <c>knowledge.lookup</c>, the tool gateway's one reference tool: a deterministic lookup in a small, fixed, in-memory
/// dataset of engineering topics. It exists to prove enforcement, not to be useful.
/// </summary>
/// <remarks>
/// <para>No I/O of any kind: no network, file system, database, process, model or external API. The dataset is compiled in.
/// A query matches a topic when, ignoring case and surrounding or repeated whitespace, it equals the topic's name or one of
/// its aliases; nothing else is matched (no search, no partial matches).</para>
/// <para>The tool decides nothing about who may call it: it runs whatever the execution authority hands it, which is only
/// ever a verified, consumed grant's call with arguments the argument policy accepted. It never logs the query and never
/// returns it: the result is dataset text only.</para>
/// </remarks>
internal sealed class KnowledgeLookupTool : IToolExecutor, ISingletonService
{
    private static readonly (string Topic, string[] Aliases, string Summary)[] Entries =
    [
        ("dependency injection", ["di"],
            "Dependency injection: a class receives the services it needs through its constructor instead of creating them, so the composition root chooses the implementations and tests can substitute them."),
        ("clean architecture", [],
            "Clean Architecture: dependencies point inwards. The domain depends on nothing, use cases depend on the domain, and adapters such as databases and web frameworks depend on the use cases."),
        ("least privilege", ["principle of least privilege"],
            "Least privilege: every user, service and agent gets only the permissions its task needs, for no longer than it needs them."),
        ("complete mediation", [],
            "Complete mediation: every access to a protected resource is checked, every time, and no path reaches the resource around the check."),
        ("prompt injection", [],
            "Prompt injection: untrusted text that tries to override an AI model's instructions. Treat model input and output as untrusted, and enforce authorization outside the model."),
        ("rate limiting", [],
            "Rate limiting: a cap on how many requests a client may make in a time window, protecting shared capacity from abuse and accidents."),
        ("defence in depth", ["defense in depth"],
            "Defence in depth: independent layers of controls, so that one control failing does not expose the system."),
        ("fail closed", ["fail secure"],
            "Fail closed: when a security check cannot complete, deny the request rather than allow it."),
        ("result pattern", [],
            "Result pattern: expected failures are returned as values carrying an error code instead of thrown as exceptions, so callers handle them explicitly."),
        ("idempotency", ["idempotence"],
            "Idempotency: an operation has the same effect however many times it is applied, which makes retrying it safe."),
    ];

    private static readonly FrozenDictionary<string, ToolOutput> ByKey = Entries
        .SelectMany(entry => entry.Aliases.Prepend(entry.Topic).Select(key => (Key: key, Output: new ToolOutput(found: true, entry.Summary))))
        .ToFrozenDictionary(pair => pair.Key, pair => pair.Output, StringComparer.Ordinal);

    public ToolId Tool { get; } = new("knowledge");

    public ActionName Action { get; } = new("lookup");

    /// <summary>How many topics the dataset holds.</summary>
    public static int TopicCount => Entries.Length;

    public ValueTask<ToolOutput> ExecuteAsync(ToolArguments arguments, CancellationToken cancellationToken)
    {
        // Another action's arguments here would be a composition error, never something to guess at.
        if (arguments is not KnowledgeLookupArguments lookup)
        {
            throw new ArgumentException("knowledge.lookup accepts only knowledge lookup arguments.", nameof(arguments));
        }

        cancellationToken.ThrowIfCancellationRequested();
        return ValueTask.FromResult(ByKey.GetValueOrDefault(Key(lookup.Query)) ?? ToolOutput.NotFound);
    }

    /// <summary>The lookup key of a query: lower case, whitespace trimmed and collapsed to single spaces.</summary>
    private static string Key(string query)
    {
        var key = new StringBuilder(query.Length);
        foreach (var character in query.Trim())
        {
            if (!char.IsWhiteSpace(character))
            {
                key.Append(char.ToLowerInvariant(character));
            }
            else if (key.Length > 0 && key[^1] != ' ')
            {
                key.Append(' ');
            }
        }

        return key.ToString();
    }
}
