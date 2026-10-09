using AgentShield.Domain.Agents;
using AgentShield.Domain.Policy;
using AgentShield.Domain.Risk;
using AgentShield.Security.Agents;
using static AgentShield.SecurityTests.Agents.AgentTestData;

namespace AgentShield.SecurityTests.Agents;

/// <summary>
/// The agent action policy over its whole input space (every combination of facts, risk levels and input decisions):
/// exact decisions and reasons, monotonicity, and decision integrity against everything the agent can influence.
/// </summary>
public sealed class AgentActionPolicyTests
{
    private static readonly SecurityDecision?[] InputDecisions = [null, SecurityDecision.Allow, SecurityDecision.Review, SecurityDecision.Block];

    private static IEnumerable<AgentActionFacts> AllFacts()
    {
        for (var mask = 0; mask < 1 << 6; mask++)
        {
            foreach (var risk in Enum.GetValues<RiskLevel>())
            {
                foreach (var input in InputDecisions)
                {
                    yield return new AgentActionFacts(
                        AgentKnown: (mask & 1) != 0,
                        CallerBound: (mask & 2) != 0,
                        ToolKnown: (mask & 4) != 0,
                        ActionKnown: (mask & 8) != 0,
                        CapabilityMatches: (mask & 16) != 0,
                        CapabilityGranted: (mask & 32) != 0,
                        Risk: risk,
                        InputDecision: input);
                }
            }
        }
    }

    [Fact]
    public void Decide_EveryCombinationOfFacts_GivesTheSpecifiedReasonAndDecision()
    {
        var facts = AllFacts().ToArray();

        Assert.All(facts, fact =>
        {
            var reason = AgentActionPolicy.Decide(fact);
            Assert.Equal(SpecifiedReason(fact), reason);
            Assert.Equal(SpecifiedDecision(fact), AgentActionReasons.DecisionFor(reason));
        });
        Assert.Equal(1024, facts.Length);
    }

    [Fact]
    public void Decide_AllowsOnlyAFullyRecognisedGrantedLowOrMediumAction_WithNoStricterInputDecision()
    {
        var allowed = AllFacts().Where(fact => Decision(fact) == SecurityDecision.Allow).ToArray();

        Assert.Equal(4, allowed.Length);
        Assert.All(allowed, fact =>
        {
            Assert.True(fact is { AgentKnown: true, CallerBound: true, ToolKnown: true, ActionKnown: true, CapabilityMatches: true, CapabilityGranted: true });
            Assert.True(fact.Risk is RiskLevel.Low or RiskLevel.Medium);
            Assert.True(fact.InputDecision is null or SecurityDecision.Allow);
        });
    }

    [Fact]
    public void Decide_AHigherRisk_NeverLowersTheDecision()
    {
        Assert.All(AllFacts(), fact => Assert.All(
            Enum.GetValues<RiskLevel>().Where(higher => higher > fact.Risk),
            higher => Assert.True(Rank(Decision(fact with { Risk = higher })) >= Rank(Decision(fact)))));
    }

    [Fact]
    public void Decide_AStricterInputDecision_NeverLowersTheDecision_AndTheResultIsNeverBelowTheInputDecision()
    {
        Assert.All(AllFacts(), fact =>
        {
            Assert.True(Rank(Decision(fact)) >= Rank(fact.InputDecision));
            Assert.All(
                InputDecisions.Where(stricter => Rank(stricter) > Rank(fact.InputDecision)),
                stricter => Assert.True(Rank(Decision(fact with { InputDecision = stricter })) >= Rank(Decision(fact))));
        });
    }

    [Fact]
    public void Decide_InputBlock_IsAlwaysBlock_AndInputReview_IsNeverAllow()
    {
        Assert.All(AllFacts().Where(fact => fact.InputDecision == SecurityDecision.Block), fact => Assert.Equal(SecurityDecision.Block, Decision(fact)));
        Assert.All(AllFacts().Where(fact => fact.InputDecision == SecurityDecision.Review), fact => Assert.NotEqual(SecurityDecision.Allow, Decision(fact)));
    }

    [Fact]
    public void Decide_LosingAnyFact_NeverMakesTheDecisionMorePermissive()
    {
        Func<AgentActionFacts, AgentActionFacts>[] losses =
        [
            fact => fact with { AgentKnown = false },
            fact => fact with { CallerBound = false },
            fact => fact with { ToolKnown = false },
            fact => fact with { ActionKnown = false },
            fact => fact with { CapabilityMatches = false },
            fact => fact with { CapabilityGranted = false },
        ];

        Assert.All(AllFacts(), fact => Assert.All(losses, lose => Assert.True(Rank(Decision(lose(fact))) >= Rank(Decision(fact)))));
    }

    [Fact]
    public void Decide_WhatTheAgentClaims_CannotTurnBlockOrReviewIntoAllow()
    {
        // Facts AgentShield establishes from its own data stay fixed; the agent controls only its claimed capability (match
        // or not) and the input decision it reports. Whatever it claims, the decision is never below the honest one.
        foreach (var fact in AllFacts().Where(fact => fact is { CapabilityMatches: true, InputDecision: null }))
        {
            var honest = Decision(fact);
            foreach (var matches in new[] { true, false })
            {
                foreach (var input in InputDecisions)
                {
                    var claimed = Decision(fact with { CapabilityMatches = matches, InputDecision = input });

                    Assert.True(Rank(claimed) >= Rank(honest), $"{fact} with match={matches}, input={input}: {claimed} < {honest}");
                    if (honest != SecurityDecision.Allow)
                    {
                        Assert.NotEqual(SecurityDecision.Allow, claimed);
                    }
                }
            }
        }
    }

    [Fact]
    public void Decide_BlockRulesPrecedeReviewRules_WhichPrecedeAllow()
    {
        // A request that trips a Block rule and a Review rule at once is blocked, never reviewed.
        var both = new AgentActionFacts(true, true, true, true, true, CapabilityGranted: false, RiskLevel.High, SecurityDecision.Review);
        var critical = new AgentActionFacts(true, true, true, true, true, true, RiskLevel.Critical, SecurityDecision.Review);

        Assert.Equal(AgentActionReason.CapabilityNotGranted, AgentActionPolicy.Decide(both));
        Assert.Equal(AgentActionReason.CriticalActionDenied, AgentActionPolicy.Decide(critical));
    }

    [Fact]
    public void Thresholds_AreReviewAtHigh_AndDenyAtCritical()
    {
        Assert.Equal(RiskLevel.High, AgentActionPolicy.ReviewAt);
        Assert.Equal(RiskLevel.Critical, AgentActionPolicy.DenyAt);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    [InlineData(-1)]
    public void Decide_UndefinedRisk_Throws_NeverReadAsLow(int risk)
    {
        var fact = new AgentActionFacts(true, true, true, true, true, true, (RiskLevel)risk, null);

        Assert.Throws<ArgumentOutOfRangeException>(() => AgentActionPolicy.Decide(fact));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(4)]
    public void Decide_UndefinedInputDecision_Throws_NeverReadAsAbsent(int input)
    {
        var fact = new AgentActionFacts(true, true, true, true, true, true, RiskLevel.Low, (SecurityDecision)input);

        Assert.Throws<ArgumentOutOfRangeException>(() => AgentActionPolicy.Decide(fact));
    }

    private static SecurityDecision Decision(AgentActionFacts fact) => AgentActionReasons.DecisionFor(AgentActionPolicy.Decide(fact));

    // The specification, written independently: which decision the facts call for, without the rule order.
    private static SecurityDecision SpecifiedDecision(AgentActionFacts fact)
    {
        var blocked = !fact.AgentKnown || !fact.CallerBound || !fact.ToolKnown || !fact.ActionKnown || !fact.CapabilityMatches
            || !fact.CapabilityGranted || fact.Risk == RiskLevel.Critical || fact.InputDecision == SecurityDecision.Block;
        if (blocked)
        {
            return SecurityDecision.Block;
        }

        return fact.Risk == RiskLevel.High || fact.InputDecision == SecurityDecision.Review ? SecurityDecision.Review : SecurityDecision.Allow;
    }

    // The documented rule order: the first rule that applies gives the reason.
    private static AgentActionReason SpecifiedReason(AgentActionFacts fact)
    {
        (bool Applies, AgentActionReason Reason)[] rules =
        [
            (!fact.AgentKnown, AgentActionReason.UnknownAgent),
            (!fact.CallerBound, AgentActionReason.CallerNotBoundToAgent),
            (!fact.ToolKnown, AgentActionReason.UnknownTool),
            (!fact.ActionKnown, AgentActionReason.UnknownAction),
            (!fact.CapabilityMatches, AgentActionReason.CapabilityMismatch),
            (!fact.CapabilityGranted, AgentActionReason.CapabilityNotGranted),
            (fact.Risk == RiskLevel.Critical, AgentActionReason.CriticalActionDenied),
            (fact.InputDecision == SecurityDecision.Block, AgentActionReason.InputBlocked),
            (fact.Risk == RiskLevel.High, AgentActionReason.HumanApprovalRequired),
            (fact.InputDecision == SecurityDecision.Review, AgentActionReason.InputHeldForReview),
        ];

        return rules.Where(rule => rule.Applies).Select(rule => rule.Reason).DefaultIfEmpty(AgentActionReason.Permitted).First();
    }
}
