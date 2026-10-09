using AgentShield.Domain.Threats;

namespace AgentShield.Application.Abstractions.Security;

/// <summary>
/// One independent, deterministic detector. Every registered implementation runs on every analysis (they are
/// resolved as <c>IEnumerable&lt;IThreatDetector&gt;</c>), so adding a detector never requires changing another.
/// </summary>
/// <remarks>
/// <para>Contract for implementations:</para>
/// <list type="bullet">
/// <item>Deterministic: the same input always yields the same findings.</item>
/// <item>Bounded: time and memory are at most linear in the input length (plus fixed limits), whatever the input.</item>
/// <item>Return an empty list for input that does not match; never throw for ordinary input. An exception is treated
/// as an unexpected failure: the analysis fails (500) rather than deciding without this detector.</item>
/// <item>Report what was found, not what to do: decisions belong to the policy engine.</item>
/// <item>Never copy the analysed content, or anything decoded from it, into a finding.</item>
/// <item>Name the detector in each finding's evidence (<see cref="FindingEvidence.Detector"/>).</item>
/// <item>Duplicates are allowed: <see cref="IFindingAggregator"/> fuses findings with the same category and code, from
/// one detector or several, before risk is assessed.</item>
/// <item>Thread-safe: detectors are normally singletons.</item>
/// </list>
/// </remarks>
public interface IThreatDetector
{
    IReadOnlyList<ThreatFinding> Detect(NormalizedInput input);
}
