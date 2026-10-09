using AgentShield.Application.Abstractions.Context;
using Microsoft.Extensions.Options;

namespace AgentShield.Infrastructure.AiCapacity;

/// <summary>
/// Startup validation of <see cref="AiCapacityOptions"/>, only when AI is enabled: a disabled application never makes an
/// AI call, so its capacity settings must not stop it from starting.
/// </summary>
/// <remarks>
/// Beyond single values, the validator rejects budgets that cannot be honoured: a client share larger than the global
/// budget, or guarantees that add up to more than the global budget for the configured analysis clients (the
/// guarantees would then be promises the gate cannot keep).
/// </remarks>
internal sealed class AiCapacityOptionsValidator(bool aiEnabled, IApiClientDirectory clients) : IValidateOptions<AiCapacityOptions>
{
    private const string Section = AiCapacityOptions.SectionName;

    public ValidateOptionsResult Validate(string? name, AiCapacityOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!aiEnabled)
        {
            return ValidateOptionsResult.Skip;
        }

        var failures = new List<string>();

        if (options.GlobalRequestsPerMinute <= 0)
        {
            failures.Add($"{Section}:GlobalRequestsPerMinute must be greater than 0.");
        }

        if (options.GlobalRequestsPerDay <= 0)
        {
            failures.Add($"{Section}:GlobalRequestsPerDay must be greater than 0.");
        }

        if (options.MaxConcurrentCalls <= 0)
        {
            failures.Add($"{Section}:MaxConcurrentCalls must be greater than 0.");
        }

        if (options.GlobalInputTokensPerMinute <= 0)
        {
            failures.Add($"{Section}:GlobalInputTokensPerMinute must be greater than 0.");
        }

        if (options.SkipWhenDeterministicBlock is null)
        {
            failures.Add($"{Section}:SkipWhenDeterministicBlock must be set (true or false).");
        }

        if (options.DefaultClient is not { } client)
        {
            failures.Add($"{Section}:DefaultClient is required.");
            return ValidateOptionsResult.Fail(failures);
        }

        ValidateClient(options, client, failures);

        var analysisClients = clients.AnalysisClientIds.Count;
        if (client.GuaranteedPerMinute > 0 && (long)analysisClients * client.GuaranteedPerMinute > options.GlobalRequestsPerMinute)
        {
            failures.Add($"{Section}: {analysisClients} analysis client(s) times DefaultClient:GuaranteedPerMinute exceed GlobalRequestsPerMinute, so the guarantees cannot all be honoured.");
        }

        if (client.GuaranteedPerDay > 0 && (long)analysisClients * client.GuaranteedPerDay > options.GlobalRequestsPerDay)
        {
            failures.Add($"{Section}: {analysisClients} analysis client(s) times DefaultClient:GuaranteedPerDay exceed GlobalRequestsPerDay, so the guarantees cannot all be honoured.");
        }

        if (client.GuaranteedInputTokensPerMinute > 0
            && (long)analysisClients * client.GuaranteedInputTokensPerMinute > options.GlobalInputTokensPerMinute)
        {
            failures.Add($"{Section}: {analysisClients} analysis client(s) times DefaultClient:GuaranteedInputTokensPerMinute exceed GlobalInputTokensPerMinute, so the guarantees cannot all be honoured.");
        }

        return failures.Count == 0 ? ValidateOptionsResult.Success : ValidateOptionsResult.Fail(failures);
    }

    private static void ValidateClient(AiCapacityOptions options, AiClientCapacityOptions client, List<string> failures)
    {
        const string Prefix = Section + ":DefaultClient";

        if (client.GuaranteedPerMinute <= 0)
        {
            failures.Add($"{Prefix}:GuaranteedPerMinute must be greater than 0.");
        }

        if (client.MaxPerMinute < client.GuaranteedPerMinute)
        {
            failures.Add($"{Prefix}:MaxPerMinute must be at least GuaranteedPerMinute.");
        }

        if (client.GuaranteedPerMinute > options.GlobalRequestsPerMinute)
        {
            failures.Add($"{Prefix}:GuaranteedPerMinute must not exceed {Section}:GlobalRequestsPerMinute.");
        }

        if (client.MaxPerMinute > options.GlobalRequestsPerMinute)
        {
            failures.Add($"{Prefix}:MaxPerMinute must not exceed {Section}:GlobalRequestsPerMinute.");
        }

        if (client.GuaranteedPerDay <= 0)
        {
            failures.Add($"{Prefix}:GuaranteedPerDay must be greater than 0.");
        }

        if (client.GuaranteedPerDay < client.GuaranteedPerMinute)
        {
            failures.Add($"{Prefix}:GuaranteedPerDay must be at least GuaranteedPerMinute (a smaller daily guarantee cannot honour the minute guarantee).");
        }

        if (client.MaxPerDay < client.GuaranteedPerDay)
        {
            failures.Add($"{Prefix}:MaxPerDay must be at least GuaranteedPerDay.");
        }

        if (client.MaxPerDay > options.GlobalRequestsPerDay)
        {
            failures.Add($"{Prefix}:MaxPerDay must not exceed {Section}:GlobalRequestsPerDay.");
        }

        if (client.MaxConcurrentCalls <= 0)
        {
            failures.Add($"{Prefix}:MaxConcurrentCalls must be greater than 0.");
        }

        if (client.MaxConcurrentCalls > options.MaxConcurrentCalls)
        {
            failures.Add($"{Prefix}:MaxConcurrentCalls must not exceed {Section}:MaxConcurrentCalls.");
        }

        if (client.GuaranteedInputTokensPerMinute <= 0)
        {
            failures.Add($"{Prefix}:GuaranteedInputTokensPerMinute must be greater than 0.");
        }

        if (client.MaxInputTokensPerMinute < client.GuaranteedInputTokensPerMinute)
        {
            failures.Add($"{Prefix}:MaxInputTokensPerMinute must be at least GuaranteedInputTokensPerMinute.");
        }

        if (client.MaxInputTokensPerMinute > options.GlobalInputTokensPerMinute)
        {
            failures.Add($"{Prefix}:MaxInputTokensPerMinute must not exceed {Section}:GlobalInputTokensPerMinute.");
        }

        if (client.WhenExceeded != AiCapacityExceededAction.Review)
        {
            failures.Add($"{Prefix}:WhenExceeded must be 'Review' (the only supported behaviour).");
        }
    }
}
