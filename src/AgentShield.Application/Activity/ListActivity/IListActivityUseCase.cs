using AgentShield.Application.Common.Results;

namespace AgentShield.Application.Activity.ListActivity;

/// <summary>Reads one page of the security activity history, optionally filtered by decision and minimum risk level.</summary>
/// <remarks>Expects a request that passed <see cref="ListActivityRequestValidator"/>. Read-only: it changes nothing.</remarks>
public interface IListActivityUseCase
{
    Task<Result<ActivityPageResponse>> ExecuteAsync(ListActivityRequest request, CancellationToken cancellationToken);
}
