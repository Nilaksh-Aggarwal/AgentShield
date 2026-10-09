using AgentShield.Infrastructure.AiCapacity;

namespace AgentShield.UnitTests.Infrastructure.AiCapacity;

/// <summary>Startup validation of the AI capacity budget: every rule, impossible combinations, and AI disabled.</summary>
public class AiCapacityOptionsValidatorTests
{
    private static readonly StaticClientDirectory TwoClients = new("client-a", "client-b");

    [Fact]
    public void Validate_CommittedDefaults_Succeed()
    {
        var result = new AiCapacityOptionsValidator(aiEnabled: true, TwoClients).Validate(null, InMemoryAiCapacityGateTests.DefaultOptions());

        Assert.True(result.Succeeded, result.FailureMessage);
    }

    public static TheoryData<string, string> InvalidSettings() => new()
    {
        { "GlobalRequestsPerMinute=0", "GlobalRequestsPerMinute must be greater than 0" },
        { "GlobalRequestsPerMinute=-1", "GlobalRequestsPerMinute must be greater than 0" },
        { "GlobalRequestsPerDay=0", "GlobalRequestsPerDay must be greater than 0" },
        { "MaxConcurrentCalls=0", "Ai:Capacity:MaxConcurrentCalls must be greater than 0" },
        { "SkipWhenDeterministicBlock=null", "SkipWhenDeterministicBlock must be set" },
        { "DefaultClient=null", "DefaultClient is required" },
        { "GuaranteedPerMinute=0", "GuaranteedPerMinute must be greater than 0" },
        { "MaxPerMinute=1", "MaxPerMinute must be at least GuaranteedPerMinute" },
        { "GuaranteedPerMinute=11", "GuaranteedPerMinute must not exceed Ai:Capacity:GlobalRequestsPerMinute" },
        { "MaxPerMinute=11", "MaxPerMinute must not exceed Ai:Capacity:GlobalRequestsPerMinute" },
        { "GuaranteedPerDay=0", "GuaranteedPerDay must be greater than 0" },
        { "GuaranteedPerDay=1", "GuaranteedPerDay must be at least GuaranteedPerMinute" },
        { "MaxPerDay=79", "MaxPerDay must be at least GuaranteedPerDay" },
        { "MaxPerDay=401", "MaxPerDay must not exceed Ai:Capacity:GlobalRequestsPerDay" },
        { "ClientMaxConcurrentCalls=0", "DefaultClient:MaxConcurrentCalls must be greater than 0" },
        { "ClientMaxConcurrentCalls=5", "DefaultClient:MaxConcurrentCalls must not exceed Ai:Capacity:MaxConcurrentCalls" },
        { "WhenExceeded=0", "WhenExceeded must be 'Review'" },
        { "WhenExceeded=2", "WhenExceeded must be 'Review'" },
        { "GlobalInputTokensPerMinute=0", "GlobalInputTokensPerMinute must be greater than 0" },
        { "GuaranteedInputTokensPerMinute=0", "GuaranteedInputTokensPerMinute must be greater than 0" },
        { "MaxInputTokensPerMinute=39999", "MaxInputTokensPerMinute must be at least GuaranteedInputTokensPerMinute" },
        { "MaxInputTokensPerMinute=200001", "MaxInputTokensPerMinute must not exceed Ai:Capacity:GlobalInputTokensPerMinute" },
        { "GuaranteedInputTokensPerMinute=100001", "times DefaultClient:GuaranteedInputTokensPerMinute exceed GlobalInputTokensPerMinute" },
    };

    [Theory]
    [MemberData(nameof(InvalidSettings))]
    public void Validate_AiEnabled_RejectsInvalidOrImpossibleSettings(string setting, string expectedMessage)
    {
        var options = InMemoryAiCapacityGateTests.DefaultOptions();
        Apply(options, setting);

        var result = new AiCapacityOptionsValidator(aiEnabled: true, TwoClients).Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains(expectedMessage, result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(5, true)]
    [InlineData(6, false)]
    public void Validate_GuaranteesForEveryAnalysisClient_MustFitTheGlobalMinuteBudget(int clients, bool valid)
    {
        // 2 guaranteed per minute each: 5 clients use exactly the 10 per minute; 6 would need 12.
        var directory = new StaticClientDirectory([.. Enumerable.Range(0, clients).Select(index => $"client-{index}")]);

        var result = new AiCapacityOptionsValidator(aiEnabled: true, directory).Validate(null, InMemoryAiCapacityGateTests.DefaultOptions());

        Assert.Equal(valid, result.Succeeded);
        if (!valid)
        {
            Assert.Contains("GuaranteedPerMinute exceed GlobalRequestsPerMinute", result.FailureMessage, StringComparison.Ordinal);
        }
    }

    [Fact]
    public void Validate_GuaranteesForEveryAnalysisClient_MustFitTheGlobalDailyBudget()
    {
        var options = InMemoryAiCapacityGateTests.DefaultOptions();
        options.GlobalRequestsPerMinute = 100;

        // 6 clients × 80 guaranteed per day = 480 > 400 (the minute guarantees fit: 12 ≤ 100).
        var directory = new StaticClientDirectory([.. Enumerable.Range(0, 6).Select(index => $"client-{index}")]);
        var result = new AiCapacityOptionsValidator(aiEnabled: true, directory).Validate(null, options);

        Assert.True(result.Failed);
        Assert.Contains("GuaranteedPerDay exceed GlobalRequestsPerDay", result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void Validate_AiDisabled_SkipsEvenCompletelyMissingSettings()
    {
        var result = new AiCapacityOptionsValidator(aiEnabled: false, TwoClients).Validate(null, new AiCapacityOptions());

        Assert.True(result.Skipped);
    }

    [Fact]
    public void Validate_AiEnabled_WithNothingConfigured_ReportsEveryMissingValue_InsteadOfInventingDefaults()
    {
        var result = new AiCapacityOptionsValidator(aiEnabled: true, TwoClients).Validate(null, new AiCapacityOptions());

        Assert.True(result.Failed);
        Assert.Equal(6, result.Failures!.Count());
    }

    [Theory]
    [InlineData("MaxPerMinute=2")] // = GuaranteedPerMinute
    [InlineData("MaxPerMinute=10")] // = GlobalRequestsPerMinute
    [InlineData("GuaranteedPerDay=2")] // = GuaranteedPerMinute
    [InlineData("MaxPerDay=80")] // = GuaranteedPerDay
    [InlineData("MaxPerDay=400")] // = GlobalRequestsPerDay
    [InlineData("ClientMaxConcurrentCalls=4")] // = MaxConcurrentCalls
    [InlineData("MaxInputTokensPerMinute=40000")] // = GuaranteedInputTokensPerMinute
    [InlineData("MaxInputTokensPerMinute=200000")] // = GlobalInputTokensPerMinute
    [InlineData("GuaranteedPerMinute=10;MaxPerMinute=10", 1)] // one client: its guarantee = GlobalRequestsPerMinute
    public void Validate_ValuesExactlyAtTheirLimit_AreAccepted(string settings, int clients = 2)
    {
        // Each limit is inclusive; the rejection cases above are one past it (mutation testing: the boundaries were unpinned).
        var options = InMemoryAiCapacityGateTests.DefaultOptions();
        foreach (var setting in settings.Split(';'))
        {
            Apply(options, setting);
        }

        var directory = clients == 1 ? new StaticClientDirectory("client-a") : TwoClients;
        var result = new AiCapacityOptionsValidator(aiEnabled: true, directory).Validate(null, options);

        Assert.True(result.Succeeded, result.FailureMessage);
    }

    private static void Apply(AiCapacityOptions options, string setting)
    {
        var client = options.DefaultClient!;
        var (name, value) = (setting.Split('=')[0], setting.Split('=')[1]);
        int Number() => int.Parse(value, System.Globalization.CultureInfo.InvariantCulture);

        switch (name)
        {
            case "GlobalRequestsPerMinute": options.GlobalRequestsPerMinute = Number(); break;
            case "GlobalRequestsPerDay": options.GlobalRequestsPerDay = Number(); break;
            case "MaxConcurrentCalls": options.MaxConcurrentCalls = Number(); break;
            case "SkipWhenDeterministicBlock": options.SkipWhenDeterministicBlock = null; break;
            case "DefaultClient": options.DefaultClient = null; break;
            case "GuaranteedPerMinute": client.GuaranteedPerMinute = Number(); break;
            case "MaxPerMinute": client.MaxPerMinute = Number(); break;
            case "GuaranteedPerDay": client.GuaranteedPerDay = Number(); break;
            case "MaxPerDay": client.MaxPerDay = Number(); break;
            case "ClientMaxConcurrentCalls": client.MaxConcurrentCalls = Number(); break;
            case "WhenExceeded": client.WhenExceeded = (AiCapacityExceededAction)Number(); break;
            case "GlobalInputTokensPerMinute": options.GlobalInputTokensPerMinute = Number(); break;
            case "GuaranteedInputTokensPerMinute": client.GuaranteedInputTokensPerMinute = Number(); break;
            case "MaxInputTokensPerMinute": client.MaxInputTokensPerMinute = Number(); break;
            default: throw new ArgumentOutOfRangeException(nameof(setting), setting, "Unknown setting.");
        }
    }
}
