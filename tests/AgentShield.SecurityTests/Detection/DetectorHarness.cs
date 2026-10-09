using AgentShield.Application.Abstractions.Security;
using AgentShield.Domain.Threats;
using AgentShield.Security.Detection;
using AgentShield.Security.Detection.Detectors;
using AgentShield.Security.Detection.Obfuscation;
using AgentShield.Security.Normalization;

namespace AgentShield.SecurityTests.Detection;

/// <summary>Runs detectors the way the pipeline does: on normalised input.</summary>
internal static class DetectorHarness
{
    private static readonly InputNormalizer Normalizer = new();

    public static PatternThreatDetector[] AllDetectors() =>
        [new InstructionOverrideDetector(), new RoleManipulationDetector(), new SecretExtractionDetector()];

    /// <summary>The obfuscation detector wired as the container wires it: over every pattern detector.</summary>
    public static ObfuscationDetector CreateObfuscationDetector() => new(Normalizer, AllDetectors());

    public static IReadOnlyList<ThreatFinding> Detect(IThreatDetector detector, string rawInput) =>
        detector.Detect(Normalizer.Normalize(rawInput));

    public static string[] Codes(IThreatDetector detector, string rawInput) =>
        Detect(detector, rawInput).Select(finding => finding.Code).ToArray();
}
