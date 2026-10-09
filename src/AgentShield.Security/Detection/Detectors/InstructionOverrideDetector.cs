using System.Text.RegularExpressions;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.Threats;

namespace AgentShield.Security.Detection.Detectors;

/// <summary>
/// Detects attempts to cancel or replace the instructions the model was given ("ignore all previous instructions").
/// </summary>
internal sealed partial class InstructionOverrideDetector()
    : PatternThreatDetector(ThreatCategory.InstructionOverride, RuleSet), ISingletonService
{
    private static readonly PatternRule[] RuleSet =
    [
        new(
            "IO-001",
            "InstructionOverride.IgnorePrevious",
            ThreatSeverity.High,
            0.9,
            "Asks the model to ignore or override its previous instructions.",
            IgnorePreviousPattern()),
        new(
            "IO-002",
            "InstructionOverride.DiscardContext",
            ThreatSeverity.High,
            0.8,
            "Asks the model to discard everything it was told before this input.",
            DiscardContextPattern()),
        new(
            "IO-003",
            "InstructionOverride.NewInstructions",
            ThreatSeverity.Medium,
            0.6,
            "Presents replacement instructions for the model to follow.",
            NewInstructionsPattern()),
    ];

    // verb … (up to 4 words) … "previous/prior/above/system…" … (up to 2 words) … "instructions/rules/prompt…"
    [GeneratedRegex(
        @"\b(?:ignore|disregard|forget|skip|override|bypass)\b(?:\W+\w+){0,4}\W+(?:previous|prior|preceding|above|earlier|original|initial|system|developer)(?:\W+\w+){0,2}\W+(?:instructions?|prompts?|rules|directions|directives|guidelines|context|commands|constraints|restrictions)\b",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex IgnorePreviousPattern();

    [GeneratedRegex(
        @"\b(?:forget|disregard|ignore)\s+(?:about\s+)?(?:everything|all)\s+(?:(?:that\s+)?you\s+(?:were|have\s+been)\s+(?:told|given|instructed)|above|before\s+this)\b",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex DiscardContextPattern();

    [GeneratedRegex(
        @"\byour\s+new\s+(?:instructions|rules|directives|task|role|objective)\s+(?:are|is)\b|\b(?:new|updated|revised|real)\s+(?:system\s+)?instructions\s*:",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex NewInstructionsPattern();
}
