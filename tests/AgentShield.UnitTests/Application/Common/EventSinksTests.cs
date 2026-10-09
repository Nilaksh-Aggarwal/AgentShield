using AgentShield.Application.Common.Events;

namespace AgentShield.UnitTests.Application.Common;

/// <summary>
/// The recording contract every audit path shares (Milestone 13, Part 14): every sink is given the entry whatever another
/// sink does, and only then is anything raised: a recording failure as itself (or several as one aggregate), otherwise a
/// cancellation. A cancelled request never leaves one sink holding an entry the others skipped.
/// </summary>
public sealed class EventSinksTests
{
    private const string Aggregate = "Recording failed in several sinks.";

    [Fact]
    public async Task PublishToEveryAsync_EverySinkGetsTheEntry_WithTheCallersToken()
    {
        using var source = new CancellationTokenSource();
        var sinks = new[] { new Sink(), new Sink(), new Sink() };

        await EventSinks.PublishToEveryAsync(sinks, "entry", Publish, Aggregate, source.Token);

        Assert.All(sinks, sink => Assert.Equal(("entry", source.Token), (sink.Received, sink.Token)));
    }

    [Fact]
    public async Task PublishToEveryAsync_OneSinkFails_TheOthersStillRecord_ThenThatFailureIsRaisedAsItself()
    {
        var failure = new InvalidOperationException("sink down");
        var sinks = new[] { new Sink(), new Sink(failure), new Sink() };

        var raised = await Assert.ThrowsAsync<InvalidOperationException>(() => EventSinks.PublishToEveryAsync(sinks, "entry", Publish, Aggregate, CancellationToken.None));

        Assert.Same(failure, raised);
        Assert.Equal(["entry", null, "entry"], sinks.Select(sink => sink.Received));
    }

    [Fact]
    public async Task PublishToEveryAsync_SeveralSinksFail_EveryOtherSinkRecords_ThenOneAggregateHoldsEveryFailure()
    {
        var first = new InvalidOperationException("first");
        var second = new IOException("second");
        var sinks = new[] { new Sink(first), new Sink(), new Sink(second) };

        var raised = await Assert.ThrowsAsync<AggregateException>(() => EventSinks.PublishToEveryAsync(sinks, "entry", Publish, Aggregate, CancellationToken.None));

        Assert.StartsWith(Aggregate, raised.Message, StringComparison.Ordinal);
        Assert.Equal([first, second], raised.InnerExceptions);
        Assert.Equal("entry", sinks[1].Received);
    }

    [Fact]
    public async Task PublishToEveryAsync_ASinkIsCancelled_EveryOtherSinkRecords_ThenTheFirstCancellationIsRaised()
    {
        var firstCancellation = new OperationCanceledException("first");
        var sinks = new[] { new Sink(firstCancellation), new Sink(), new Sink(new TaskCanceledException("second")), new Sink() };

        var raised = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => EventSinks.PublishToEveryAsync(sinks, "entry", Publish, Aggregate, CancellationToken.None));

        Assert.Same(firstCancellation, raised);
        Assert.Equal([null, "entry", null, "entry"], sinks.Select(sink => sink.Received));
    }

    [Fact]
    public async Task PublishToEveryAsync_AFailureAndACancellation_TheFailureWins_AfterEverySinkWasTried()
    {
        var failure = new InvalidOperationException("sink down");
        var sinks = new[] { new Sink(new OperationCanceledException()), new Sink(failure), new Sink() };

        var raised = await Assert.ThrowsAsync<InvalidOperationException>(() => EventSinks.PublishToEveryAsync(sinks, "entry", Publish, Aggregate, CancellationToken.None));

        Assert.Same(failure, raised);
        Assert.Equal("entry", sinks[2].Received);
    }

    [Fact]
    public async Task PublishToEveryAsync_NoSinks_RecordsNothing_AndRaisesNothing()
    {
        await EventSinks.PublishToEveryAsync(Array.Empty<Sink>(), "entry", Publish, Aggregate, CancellationToken.None);
    }

    [Fact]
    public async Task PublishToEveryAsync_RequiresSinksAndAPublisher()
    {
        await Assert.ThrowsAsync<ArgumentNullException>(() => EventSinks.PublishToEveryAsync<Sink, string>(null!, "entry", Publish, Aggregate, CancellationToken.None));
        await Assert.ThrowsAsync<ArgumentNullException>(() => EventSinks.PublishToEveryAsync([new Sink()], "entry", null!, Aggregate, CancellationToken.None));
    }

    private static ValueTask Publish(Sink sink, string value, CancellationToken cancellationToken) => sink.RecordAsync(value, cancellationToken);

    private sealed class Sink(Exception? failure = null)
    {
        public string? Received { get; private set; }

        public CancellationToken Token { get; private set; }

        public ValueTask RecordAsync(string value, CancellationToken cancellationToken)
        {
            if (failure is not null)
            {
                return ValueTask.FromException(failure);
            }

            (Received, Token) = (value, cancellationToken);
            return ValueTask.CompletedTask;
        }
    }
}
