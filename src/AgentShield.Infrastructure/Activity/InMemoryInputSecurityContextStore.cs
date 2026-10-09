using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Application.Abstractions.Security;
using AgentShield.Domain.SecurityEvents;

namespace AgentShield.Infrastructure.Activity;

/// <summary>
/// Recent firewall decisions, in memory and bounded, per process. Expired analyses are dropped as new ones arrive; beyond the
/// bound the oldest is dropped, which can only make a later reference fail (a tool call referencing it is then blocked), never
/// succeed.
/// </summary>
internal sealed class InMemoryInputSecurityContextStore(TimeProvider timeProvider) : IInputSecurityContextStore, ISingletonService
{
    public const int Capacity = 10_000;

    private readonly Lock _lock = new();
    private readonly Dictionary<SecurityEventId, InputSecurityContext> _contexts = [];
    private readonly Queue<SecurityEventId> _order = new();

    public ValueTask RecordAsync(InputSecurityContext context, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        var now = timeProvider.GetUtcNow();
        lock (_lock)
        {
            // Oldest first: drop what has expired, then whatever exceeds the bound.
            while (_order.TryPeek(out var oldest) && (_contexts.Count >= Capacity || now >= _contexts[oldest].ExpiresAt))
            {
                _contexts.Remove(_order.Dequeue());
            }

            if (_contexts.TryAdd(context.SecurityEventId, context))
            {
                _order.Enqueue(context.SecurityEventId);
            }
        }

        return ValueTask.CompletedTask;
    }

    public InputSecurityContext? Find(SecurityEventId securityEventId)
    {
        lock (_lock)
        {
            return _contexts.GetValueOrDefault(securityEventId);
        }
    }
}
