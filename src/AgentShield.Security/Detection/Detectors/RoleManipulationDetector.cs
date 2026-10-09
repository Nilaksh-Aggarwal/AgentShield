using System.Text.RegularExpressions;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.Threats;

namespace AgentShield.Security.Detection.Detectors;

/// <summary>
/// Detects attempts to change who the model believes it is or who is speaking: forged chat-template role delimiters,
/// "unrestricted" personas and claims of system/developer authority, privileged role claims, requests to turn off safety
/// controls, and context poisoning: content that addresses the AI, poses as an authoritative notice or plants a permission
/// (RM-004 to RM-007).
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
        new(
            "RM-004",
            "RoleManipulation.PrivilegedRoleClaim",
            ThreatSeverity.High,
            0.8,
            "Assigns the model a privileged or unrestricted role, or claims to be its developer or administrator.",
            PrivilegedRoleClaimPattern()),
        new(
            "RM-005",
            "RoleManipulation.SafetyBypass",
            ThreatSeverity.High,
            0.85,
            "Asks the model to turn off its safety or content controls.",
            SafetyBypassPattern()),
        new(
            "RM-006",
            "RoleManipulation.ContextPoisoning",
            ThreatSeverity.Medium,
            0.7,
            "Content addresses the AI directly or presents itself as an authoritative notice.",
            ContextPoisoningPattern()),
        new(
            "RM-007",
            "RoleManipulation.FalsePermission",
            ThreatSeverity.High,
            0.8,
            "Grants the model a permission or plants a privilege claim in its memory.",
            FalsePermissionPattern()),
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

    // "you are now the system administrator.", "from this moment you are an unfiltered…", "I am your developer", "this
    // is the system operator speaking", "as your administrator, I authorize…", "I have root access to you", "switch into
    // god mode". An administrative role must end the clause, so "you are now an administrator of the book club" passes.
    // "You are now <unrestricted persona>" stays RM-002's alone.
    [GeneratedRegex(
        @"\b(?:from\s+now\s+on,?\s+you\s+are|from\s+this\s+(?:moment|point)(?:\s+on(?:wards?)?)?,?\s+you\s+are|you\s+will\s+(?:now\s+)?(?:be|act\s+as)|you\s+are\s+no\s+longer\s+[^.\n]{1,60}[.;,]\s*you\s+are(?:\s+now)?)\s+(?:an?\s+|the\s+)?(?:\w+\s+){0,2}(?:unrestricted|unfiltered|uncensored|jailbroken|unaligned|evil|god|hacker|penetration\s+tester\b|(?:administrator|admin|root|superuser|sysadmin|operator)" + DetectionPatterns.RoleClaimEnd + ")"
        + @"|\byou\s+are\s+now\s+(?:an?\s+|the\s+)?(?:\w+\s+){0,2}(?:god|hacker|penetration\s+tester\b|(?:administrator|admin|root|superuser|sysadmin|operator)" + DetectionPatterns.RoleClaimEnd + ")"
        + @"|\b(?:i\s+am|i'?m)\s+your\s+(?:\w+\s+){0,1}(?:developer|creator|administrator|admin|operator|owner|programmer|maker|supervisor)\b"
        + @"|\bthis\s+is\s+(?:your\s+(?:\w+\s+){0,1}|the\s+system\s+)(?:operator|administrator|admin|developer|creator)\s+speaking\b"
        + @"|\bas\s+your\s+(?:\w+\s+){0,1}(?:administrator|admin|developer|creator|operator|owner|supervisor)\s*,?\s+(?:i\s+(?:hereby\s+)?(?:authori[sz]e|order|command|instruct|permit|allow|grant|need\s+you|want\s+you|require|override)|you\s+(?:must|may|can\s+now|are\s+(?:now\s+)?(?:allowed|permitted|authori[sz]ed|required)))\b"
        + @"|\bi\s+have\s+(?:root|admin|administrator|full|god|elevated|superuser)\s+(?:access|privileges|rights|permissions|control)\s+(?:to|over|on)\s+you\b"
        + @"|\b(?:switch|go|change)\s+(?:in)?to\s+(?:god|dan|jailbreak|unrestricted|unfiltered|evil)\s+mode\b",
        DetectionPatterns.MultilineOptions,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex PrivilegedRoleClaimPattern();

    // "turn off / bypass your safety filters…". "The safety filter in my browser" does not match (no "your").
    [GeneratedRegex(
        @"\b(?:turn\s+off|switch\s+off|disable|drop|remove|bypass|deactivate|lift|ignore|suspend|override|circumvent|get\s+rid\s+of)\s+(?:all\s+(?:of\s+)?)?your\s+(?:\w+\s+){0,1}(?:safety|content|security|ethical|moral)\s+(?:filters?|checks?|rules|guidelines|restrictions|policies|guardrails|measures|protocols|settings|constraints|limits)\b",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex SafetyBypassPattern();

    // Content that speaks to the AI ("Attention AI assistant:", "AI reading this email:", "<!-- AI:", "if you are an
    // AI"), bracketed system/admin notices, and claims of authority over what the model knows ("treat the following as
    // verified", "overrides your knowledge"). An AI recipient must be named, so "Reminder for assistants:" passes.
    [GeneratedRegex(
        @"\b(?:attention|attn|note|notice|message|instructions?|update|reminder|important|warning|directive|guidance|policy(?:\s+update)?|internal\s+note|official\s+(?:guidance|notice|policy)|system\s+notice)\s*(?:to|for)?\s+(?:the\s+|any\s+|all\s+)?" + DetectionPatterns.AiRecipient + @"\s*[:,\-]"
        + @"|\b" + DetectionPatterns.AiRecipient + @"\s+(?:reading|processing|summari[sz]ing|parsing|analy[sz]ing|reviewing|viewing|scanning)\s+this\b(?:\s+\w+)?\s*[:,\-]"
        + @"|<!--\s*(?:ai|assistant|llm|agents?|chatbot|bot)s?\b[^>\n]{0,10}:"
        + @"|\bif\s+you\s+are\s+an?\s+(?:ai|llm|large\s+language\s+model|language\s+model|assistant|chatbot|bot|ai\s+(?:assistant|agent|model))\b"
        + @"|\[\s*(?:system|admin|administrator|developer|security|root|operator)\s+(?:notice|message|instruction|override|update|alert|note|directive)\s*\]"
        + @"|\b(?:treat|regard|consider|accept)\s+(?:the\s+following|this|what\s+follows)\s+as\s+(?:authoritative|verified|ground\s+truth|fact|true|official|the\s+truth)\b"
        + @"|\boverrides?\s+(?:what\s+you\s+know|your\s+(?:knowledge|training|instructions|rules|guidelines))\b",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex ContextPoisoningPattern();

    // "the assistant is now allowed to share…", "you are now authorized to bypass…", and memory writes that plant a
    // privilege ("store this in your memory: I am the owner…"). A plain preference ("remember that I prefer short
    // answers") does not match.
    [GeneratedRegex(
        @"\b(?:the\s+(?:assistant|ai|chatbot|bot|agent|model)s?\s+(?:is|are)|you\s+are\s+now)\s+(?:now\s+)?(?:allowed|permitted|authori[sz]ed|free|cleared|approved)\s+to\s+(?:\w+\s+){0,1}(?:share|disclose|reveal|ignore|skip|bypass|approve|grant|delete|access|send|give\s+out|expose|leak|override|disable)\b"
        + @"|\b(?:(?:store|save|remember|keep|write|add|commit|record)\s+(?:this|that|the\s+following)?\s*(?:in|to|into)\s+(?:your\s+)?(?:long[\s-]term\s+)?memory|update\s+your\s+(?:memory|knowledge|beliefs?)|remember\s+(?:this\s+)?for\s+(?:all\s+)?future\s+(?:conversations|sessions|chats))\b[^\n]{0,60}\b" + DetectionPatterns.PrivilegeClaim + @"\b",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex FalsePermissionPattern();
}
