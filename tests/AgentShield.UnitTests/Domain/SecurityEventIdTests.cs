using AgentShield.Domain.SecurityEvents;

namespace AgentShield.UnitTests.Domain;

public class SecurityEventIdTests
{
    [Fact]
    public void New_CreatesDistinctNonEmptyIds()
    {
        var first = SecurityEventId.New();
        var second = SecurityEventId.New();

        Assert.NotEqual(Guid.Empty, first.Value);
        Assert.NotEqual(first, second);
    }

    [Fact]
    public void From_RejectsEmptyGuid()
    {
        Assert.Throws<ArgumentException>(() => SecurityEventId.From(Guid.Empty));
    }

    [Fact]
    public void From_RoundTripsValue()
    {
        var value = Guid.NewGuid();

        Assert.Equal(value, SecurityEventId.From(value).Value);
    }
}
