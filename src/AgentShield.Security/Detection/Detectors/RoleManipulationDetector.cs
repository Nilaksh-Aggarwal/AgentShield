using System.Text.RegularExpressions;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.Threats;

namespace AgentShield.Security.Detection.Detectors;

/// <summary>
/// Detects attempts to change who the model believes it is or who is speaking: forged chat-template role delimiters,
/// "unrestricted" personas and claims of system/developer authority.
/// </summary>
internal sealed partial class RoleManipulationDetector()
    : PatternThreatDetector(ThreatCategory.RoleManipulation, RuleSet), ISingletonService
{
    private static readonly PatternRule[] RuleSet =
    [
        new(
            "RM-001",
            "RoleManipulation.ForgedRoleDelimiter",
            ThreatSeverity.Critical,
            0.95,
            "Contains chat-template control tokens that forge a system or assistant turn.",
            ForgedRoleDelimiterPattern()),
        new(
            "RM-002",
            "RoleManipulation.UnrestrictedPersona",
            ThreatSeverity.High,
            0.85,
            "Asks the model to adopt a persona without its safety rules.",
            UnrestrictedPersonaPattern()),
        new(
            "RM-003",
            "RoleManipulation.AuthorityClaim",
            ThreatSeverity.Medium,
            0.6,
            "Presents text as coming from the system, developer or an administrator.",
            AuthorityClaimPattern()),
    ];

    // ChatML (<|im_start|>), Llama 3 (<|start_header_id|>), GPT (<|endoftext|>) and Llama 2 ([INST], <<SYS>>) tokens.
    // Legitimate user or document text has no reason to contain them.
    [GeneratedRegex(
        @"<\|\s*(?:im_start|im_end|im_sep|system|endoftext|begin_of_text|start_header_id|end_header_id|eot_id)\s*\|>|\[/?INST\]|<</?SYS>>",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex ForgedRoleDelimiterPattern();

    [GeneratedRegex(
        @"\byou\s+are\s+now\s+(?:DAN\b|(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|unaligned|evil)\b)"
        + @"|\b(?:act|behave|respond)\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|unaligned)\b"
        + @"|\bpretend\s+(?:that\s+)?you\s+(?:have\s+no|are\s+free\s+(?:of|from)|are\s+not\s+bound\s+by|aren['’]t\s+bound\s+by|do\s+not\s+have(?:\s+any)?|don['’]t\s+have(?:\s+any)?)\s+(?:\w+\s+){0,2}(?:restrictions|rules|guidelines|filters|limits|limitations|policies)\b"
        + @"|\b(?:developer|god|DAN|jailbreak)\s+mode\s+(?:enabled|activated)\b"
        + @"|\b(?:enable|activate|enter)\s+(?:DAN|jailbreak|god)\s+mode\b"
        + @"|\bdo\s+anything\s+now\b",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex UnrestrictedPersonaPattern();

    // A line that opens as a system/developer header ("### System:", "[SYSTEM]") or an explicit override command.
    [GeneratedRegex(
        @"^[ \t]*(?:#{1,3}[ \t]*|\[)(?:system|developer)(?:[ \t]+(?:prompt|message|instructions?))?[ \t]*(?:\]|:)"
        + @"|\b(?:system|admin|administrator|developer|root)\s+(?:override|command|instruction)s?\s*:",
        DetectionPatterns.Options | RegexOptions.Multiline,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex AuthorityClaimPattern();
}
