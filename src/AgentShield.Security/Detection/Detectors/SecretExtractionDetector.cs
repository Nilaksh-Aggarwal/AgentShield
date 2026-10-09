using System.Text.RegularExpressions;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.Threats;

namespace AgentShield.Security.Detection.Detectors;

/// <summary>
/// Detects attempts to make the model disclose its hidden instructions or credentials it can reach.
/// </summary>
internal sealed partial class SecretExtractionDetector()
    : PatternThreatDetector(ThreatCategory.SecretExtraction, RuleSet), ISingletonService
{
    private static readonly PatternRule[] RuleSet =
    [
        new(
            "SE-001",
            "SecretExtraction.SystemPromptDisclosure",
            ThreatSeverity.High,
            0.85,
            "Asks the model to disclose its system prompt or hidden instructions.",
            SystemPromptDisclosurePattern()),
        new(
            "SE-002",
            "SecretExtraction.CredentialDisclosure",
            ThreatSeverity.High,
            0.75,
            "Asks the model to disclose credentials, keys or other secrets.",
            CredentialDisclosurePattern()),
    ];

    // Imperative disclosure verb … "your/the" … "system/hidden/initial…" "prompt/instructions…", or
    // "repeat everything above" (the classic prompt-leak request).
    [GeneratedRegex(
        @"\b(?:reveal|show|print|display|output|repeat|recite|leak|dump|expose|share|tell\s+me|give\s+me)\s+(?:me\s+)?(?:\w+\s+){0,2}(?:your|the)\s+(?:\w+\s+)?(?:system|initial|original|hidden|secret|internal|developer)\s+(?:prompts?|instructions|messages?|rules|guidelines|configuration)\b"
        + @"|\brepeat\s+(?:everything|all\s+(?:the\s+)?text|the\s+(?:words|text))\s+above\b",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex SystemPromptDisclosurePattern();

    [GeneratedRegex(
        @"\b(?:reveal|show|print|display|output|leak|dump|expose|list|send|share|tell\s+me|give\s+me)\s+(?:me\s+)?(?:your|the|all|any)\s+(?:\w+\s+){0,2}(?:api[\s_-]?keys?|secret[\s_-]?keys?|access[\s_-]?tokens?|auth(?:entication)?[\s_-]?tokens?|private[\s_-]?keys?|passwords?|credentials|connection[\s_-]?strings?|environment\s+variables|env\s+vars?|\.env)\b",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex CredentialDisclosurePattern();
}
