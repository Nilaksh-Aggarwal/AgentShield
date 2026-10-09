namespace AgentShield.Security.Detection;

/// <summary>
/// A detector whose rules are pure functions of text, so they can be re-applied to content derived from the input
/// (decoded or unmasked text) by <see cref="Obfuscation.ObfuscationDetector"/>.
/// </summary>
/// <remarks>
/// Every <see cref="PatternThreatDetector"/> implements it and is registered against it by convention, so a new pattern
/// detector is automatically applied to decoded content too. It is a separate interface from <c>IThreatDetector</c> on
/// purpose: the obfuscation detector cannot depend on <c>IEnumerable&lt;IThreatDetector&gt;</c> (it is one itself, a
/// circular dependency), and it must never re-run itself on its own output (unbounded recursion).
/// </remarks>
internal interface IPatternRuleSource
{
    IReadOnlyList<PatternRule> Rules { get; }
}
