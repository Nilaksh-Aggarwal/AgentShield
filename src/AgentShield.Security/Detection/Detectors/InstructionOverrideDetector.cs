using System.Text.RegularExpressions;
using AgentShield.Application.Abstractions.DependencyInjection;
using AgentShield.Domain.Threats;

namespace AgentShield.Security.Detection.Detectors;

/// <summary>
/// Detects attempts to cancel or replace the instructions the model was given ("ignore all previous instructions"), and
/// instructions that steer the agent into misusing its tools: destructive or mass changes, covert actions, approval
/// bypass, bulk data transfer and privilege escalation (IO-006 to IO-010).
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
        new(
            "IO-004",
            "InstructionOverride.RevokedInstructions",
            ThreatSeverity.High,
            0.8,
            "Declares the model's instructions revoked, void or no longer in effect.",
            RevokedInstructionsPattern()),
        new(
            "IO-005",
            "InstructionOverride.AbandonInstructions",
            ThreatSeverity.High,
            0.8,
            "Tells the model to stop following or set aside its own instructions.",
            AbandonInstructionsPattern()),
        new(
            "IO-006",
            "InstructionOverride.ToolMisuse",
            ThreatSeverity.Medium,
            0.7,
            "Instructs a destructive or mass change through the agent's tools.",
            ToolMisusePattern()),
        new(
            "IO-007",
            "InstructionOverride.CovertAction",
            ThreatSeverity.High,
            0.8,
            "Instructs an action hidden from the user or from audit logging.",
            CovertActionPattern()),
        new(
            "IO-008",
            "InstructionOverride.ApprovalBypass",
            ThreatSeverity.High,
            0.75,
            "Instructs a payment or similar action without the required approval.",
            ApprovalBypassPattern()),
        new(
            "IO-009",
            "InstructionOverride.BulkDataTransfer",
            ThreatSeverity.High,
            0.75,
            "Instructs sending an entire set of personal or business data outside.",
            BulkDataTransferPattern()),
        new(
            "IO-010",
            "InstructionOverride.PrivilegeEscalation",
            ThreatSeverity.Medium,
            0.7,
            "Instructs granting elevated access or an administrative role.",
            PrivilegeEscalationPattern()),
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

    // "your rules are revoked / no longer apply", "previous instructions are void", "the rules you were given no longer
    // apply", "act as if you never received instructions". Generic forms need previous/prior… and a strong verdict, so
    // release notes ("the previous configuration has been replaced") do not match.
    [GeneratedRegex(
        @"\byour\s+(?:\w+\s+){0,1}(?:instructions?|rules|guidelines|directions|directives|prompts?|guidance|programming|restrictions)\s+(?:\w+\s+){0,3}(?:(?:are|is|have\s+been|has\s+been)\s+(?:now\s+)?(?:no\s+longer\s+(?:valid|in\s+effect|active|relevant|applicable)|void|null|revoked|cancell?ed|obsolete|outdated|superseded|replaced|overridden|suspended|lifted|disabled|deactivated|invalid|rescinded|withdrawn)|no\s+longer\s+(?:apply|applies|matter|matters|count|hold))\b"
        + @"|\b(?:previous|prior|earlier|original|initial|preceding|above)\s+(?:instructions|rules|guidelines|directives|prompts)\s+(?:(?:are|is|have\s+been)\s+(?:now\s+)?(?:void|null|revoked|cancell?ed|obsolete|outdated|superseded|overridden|suspended|invalid|rescinded|no\s+longer\s+(?:valid|in\s+effect|active|applicable))|no\s+longer\s+appl(?:y|ies))\b"
        + @"|\b(?:instructions|rules|guidelines|directions|directives|restrictions)\s+(?:that\s+)?you\s+(?:were|have\s+been)\s+(?:given|told|provided)\s+(?:\w+\s+){0,4}(?:no\s+longer\s+(?:apply|matter|count)|(?:are|is)\s+(?:now\s+)?(?:void|null|cancell?ed|revoked|obsolete|invalid))\b"
        + @"|\b(?:instructions|rules|guidelines|directions)\s+(?:given\s+to\s+you|you\s+(?:received|got))\s+(?:\w+\s+){0,4}(?:are|is)\s+(?:now\s+)?(?:void|null|cancell?ed|revoked|obsolete|invalid|no\s+longer\s+valid)\b"
        + @"|\b(?:as\s+if|pretend(?:\s+that)?)\s+you\s+(?:never|did\s+not|didn'?t|have\s+not|haven'?t)\s+(?:receive[d]?|get|got|been\s+given|had)\s+(?:any\s+)?(?:\w+\s+){0,1}(?:instructions|rules|guidelines|system\s+prompt)\b",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex RevokedInstructionsPattern();

    // "abandon / set aside your rules", "stop following your original instructions", "ignore the rules you were given",
    // "these instructions take precedence over your system prompt". Requires "your" or a previous/system qualifier, so
    // "don't follow the instructions on the box" does not match; configuration is left out ("override your default
    // configuration with environment variables" is ordinary documentation). The verbs IO-001 already covers (ignore,
    // forget…) match only "your <instructions>" with nothing in between, so IO-001 alone reports "ignore your previous rules".
    [GeneratedRegex(
        @"\b(?:abandon|discard|drop|scrap|ditch|throw\s+(?:out|away)|set\s+aside|put\s+aside)\s+(?:all\s+(?:of\s+)?)?your\s+(?:\w+\s+){0,2}(?:instructions?|rules|guidelines|directions|directives|system\s+prompt|prompts?|programming|guardrails|principles|restrictions|policies|constraints|training)\b"
        + @"|\b(?:forget|disregard|ignore|override|bypass|skip)\s+(?:all\s+(?:of\s+)?)?your\s+(?:own\s+)?(?:instructions?|rules|guidelines|directions|directives|system\s+prompt|prompts?|programming|guardrails|principles|restrictions|policies|constraints|training)\b"
        + @"|\b(?:do\s+not|don'?t|stop|cease|no\s+longer|never\s+again)\s+(?:follow|obey|adhere\s+to|comply\s+with|listen\s+to|respect|abide\s+by)(?:ing)?\s+(?:your\s+(?:\w+\s+){0,1}|(?:the\s+|any\s+)?(?:previous|prior|earlier|original|initial|system|developer|above)\s+(?:\w+\s+){0,1})(?:instructions?|rules|guidelines|directions|directives|prompts?|programming|configuration|constraints)\b"
        + @"|\b(?:abandon|discard|drop|scrap|ditch|throw\s+(?:out|away)|set\s+aside|put\s+aside|forget|disregard|ignore|override|bypass)\s+(?:all\s+)?(?:the\s+|any\s+)?(?:instructions|rules|guidelines|directions|directives)\s+(?:that\s+)?you\s+(?:were\s+given|received|got|have\s+been\s+given|were\s+told)\b"
        + @"|\b(?:these|my|this|the\s+following|the\s+below)\s+(?:\w+\s+){0,1}(?:instructions?|rules|directions|message|commands?|orders)\s+(?:take|takes|have|has)\s+(?:precedence|priority)\s+over\s+(?:your\b|anything\s+(?:in|from)\s+your\b|(?:the\s+)?system\s+prompt|(?:all\s+|any\s+)?(?:previous|prior|earlier|original)\s+(?:instructions|rules|guidelines))",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex AbandonInstructionsPattern();

    // Mass deletion of accounts, records, backups…; setting every salary/balance/password to zero or admin; rm -rf /,
    // drop_*() calls; wiping backups or logs. Ordinary single-item requests ("delete the draft") do not match.
    [GeneratedRegex(
        @"\b(?:delete|drop|wipe|erase|truncate|destroy|purge|remove|nuke|overwrite|corrupt)\s+(?:\S+\s+){0,2}(?:all|every|each|entire|whole)\s+(?:\S+\s+){0,2}(?:user\s+accounts|accounts|users|records|databases?|tables?|backups?|repositor(?:y|ies)|logs|invoices|orders|customers|employees|buckets?)\b"
        + @"|\b(?:change|set|update|modify|reset|zero\s+out)\s+(?:all|every|each)\s+(?:\S+\s+){0,2}(?:salar(?:y|ies)|prices?|balances?|passwords?|permissions?|roles?|records?|accounts?)\s+to\s+(?:zero|0|\$0|null|nothing|empty|blank|none|admin|root|public)\b"
        + @"|\brm\s+-(?:rf|fr|r)\s+/|\b(?:drop|delete|wipe|truncate|purge|destroy)_\w+\s*\(|\b(?:wipe|erase|destroy|purge)\s+(?:the\s+)?(?:\S+\s+){0,1}(?:backups?|databases?|audit\s+logs?|logs)\b",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex ToolMisusePattern();

    // "silently forward…", "<action> … without telling the user", "don't log it", a command to disable audit logging.
    // "without telling anyone" needs an action verb next to it, so a surprise party does not match.
    [GeneratedRegex(
        @"\b(?:silently|secretly|covertly|quietly|discreetly|stealthily)\s+(?:\w+\s+){0,1}(?:send|forward|copy|transfer|delete|grant|change|move|upload|export|disable|run|execute|install|e-?mail|share|add|remove|modify|exfiltrate|redirect)\b"
        + @"|\b(?:send|forward|copy|transfer|delete|grant|change|move|upload|export|disable|run|execute|install|e-?mail|share|give|add|remove|modify|redirect)\w*\b[^.!?\n]{0,60}\bwithout\s+(?:telling|notifying|informing|alerting)\s+(?:the\s+)?(?:user|users|anyone|anybody|owner|customer|admin|administrator|security|them)\b"
        + @"|\bwithout\s+(?:telling|notifying|informing|alerting)\s+(?:the\s+)?(?:user|users|anyone|anybody|owner|customer|admin|administrator|security|them)\s*[,;:]?\s*(?:send|forward|copy|transfer|delete|grant|change|move|upload|export|disable|run|execute|install|e-?mail|share|give|add|remove|modify|redirect)\b"
        + @"|\b(?:do\s+not|don'?t|never)\s+(?:log|record|audit)\s+(?:it|this|that|the\s+(?:action|change|transfer|request))\b"
        + "|" + DetectionPatterns.ImperativeStart + @"(?:disable|turn\s+off|stop|delete|clear|wipe|bypass|tamper\s+with|switch\s+off)\s+(?:the\s+)?(?:\S+\s+){0,1}(?:audit|security|activity)\s*(?:logs?|logging|trail|monitoring|alerts?)\b",
        DetectionPatterns.MultilineOptions,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex CovertActionPattern();

    // A payment, transfer, refund, grant or approval "without approval / with no sign-off needed", or a request to skip
    // the approval process. Limited to money and permission verbs, so "deployed to staging without approval" does not
    // match.
    [GeneratedRegex(
        @"\b(?:pay|payment|transfer|refund|wire|purchase|withdraw|grant|approve|release|reimburs)\w*\b[^.!?\n]{0,60}\b(?:without\s+(?:any\s+|the\s+|asking\s+for\s+|waiting\s+for\s+|getting\s+|requesting\s+)?(?:approval|confirmation|sign-?off|consent|a\s+second\s+approval|checking\s+with\s+(?:anyone|anybody|a\s+manager|the\s+user))|(?:with\s+)?no\s+(?:approval|confirmation|sign-?off)\s+(?:needed|required|necessary))\b"
        + @"|\b(?:skip|bypass|ignore|circumvent|override|avoid|get\s+around)\s+(?:the\s+)?(?:usual\s+|normal\s+|required\s+)?(?:approval|authori[sz]ation|sign-?off)\s*(?:process|step|steps|check|checks|workflow|flow|requirement)?\b",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex ApprovalBypassPattern();

    // "send the entire customer database to x@y / an external bucket": a whole set of personal or business data to an
    // address, URL or outside place. "Send all customer invoices to accounting" does not match (no whole dataset).
    [GeneratedRegex(
        @"\b(?:send|e-?mail|forward|upload|post|transfer|copy|export|share|sync|move|leak|exfiltrate|dump)\s+(?:\S+\s+){0,2}(?:entire|whole|full|complete|all\s+(?:the\s+)?|every)\s+(?:\S+\s+){0,1}(?:customer|client|user|employee|patient|payroll|personal|private|sensitive|confidential|financial|medical|hr)\s+(?:\S+\s+){0,1}(?:database|list|records|data|dataset|table|export|dump|files|contacts|details)\b[^\n]{0,60}\b(?:to|into|onto)\s+(?:an?\s+|the\s+|my\s+|their\s+)?(?:[\w.+-]+@[\w-]+(?:\.[\w-]+)+|https?://|external|outside|third[\s-]party|personal|private|unknown|public|another|other|competitor)",
        DetectionPatterns.Options,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex BulkDataTransferPattern();

    // A command (not a question) to grant me/my account admin rights, elevate my access, or make me an admin.
    [GeneratedRegex(
        DetectionPatterns.ImperativeStart + @"(?:(?:grant|give|assign|add)\s+(?:me|myself|my\s+(?:\w+\s+){0,1}account|this\s+(?:user|account))\s+(?:\w+\s+){0,1}(?:admin|administrator|root|superuser|owner|full|elevated|unrestricted|god)\s+(?:access|rights|privileges|permissions|role|control)|(?:elevate|escalate)\s+my\s+(?:\w+\s+){0,1}(?:access|privileges?|permissions?|role|rights|clearance)|(?:make|promote)\s+(?:me|my\s+account)\s+(?:an?\s+)?(?:admin|administrator|superuser|owner|root))\b",
        DetectionPatterns.MultilineOptions,
        DetectionPatterns.TimeoutMilliseconds)]
    private static partial Regex PrivilegeEscalationPattern();
}
