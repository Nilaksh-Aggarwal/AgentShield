using System.Text.RegularExpressions;

namespace AgentShield.Security.Detection;

/// <summary>Regex settings shared by every detection pattern (untrusted input: linear time, bounded runtime).</summary>
internal static class DetectionPatterns
{
    /// <summary>
    /// Case-insensitive, culture-invariant and <see cref="RegexOptions.NonBacktracking"/>: matching time is linear in
    /// the input length, so crafted input cannot trigger catastrophic backtracking (ReDoS). Patterns therefore cannot
    /// use lookarounds, backreferences or atomic groups.
    /// </summary>
    public const RegexOptions Options = RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking;

    /// <summary>Upper bound per pattern evaluation; a timeout fails the analysis (see <see cref="PatternThreatDetector"/>).</summary>
    public const int TimeoutMilliseconds = 250;

    /// <summary><see cref="Options"/> with <c>^</c> and <c>$</c> at line boundaries, for rules anchored to a sentence or line.</summary>
    public const RegexOptions MultilineOptions = Options | RegexOptions.Multiline;

    // Shared fragments of the reliability rules (2026-10-09). Without lookarounds, a rule that must not fire on a
    // question or a description consumes what has to precede or follow instead.

    /// <summary>The start of a command: a line or clause start, or a word that introduces one ("please", "then").</summary>
    public const string ImperativeStart = @"(?:^|[.!:;,]\s*|\b(?:please|now|just|then|and|also|first|immediately)\s+)";

    /// <summary>Credentials and secrets a request may try to move out of the system.</summary>
    public const string CredentialNouns =
        @"(?:api[\s_-]?keys?|secret[\s_-]?keys?|(?:secret\s+)?access[\s_-]?keys?|(?:access|auth(?:entication)?|bearer|refresh|session|oauth)[\s_-]?tokens?|session[\s_-]?cookies?|private[\s_-]?keys?|ssh[\s_-]?keys?|client[\s_-]?secrets?|passwords?|passphrases?|passcodes?|credentials|login\s+details|connection[\s_-]?strings?|environment\s+variables|env\s+vars?|\.env(?:\s+file)?|secrets\.json|(?:credit|debit|bank)\s+card\s+(?:numbers?|details)|card\s+numbers?)";

    /// <summary>Where moved data ends up: a person, an address, a URL, an outside place, or the reply itself.</summary>
    public const string Destination =
        @"(?:(?:to|into|onto|via|at)\s+(?:me\b|us\b|[\w.+-]+@[\w-]+(?:\.[\w-]+)+|https?://|(?:my|our|this|that|an?|the|some)\s+(?:\S+\s+){0,2}(?:server|e-?mail|address|inbox|webhook|bucket|endpoint|url|site|website|channel|drive|pastebin|paste|gist|form))|\bhere\b|\bin(?:to)?\s+(?:your|the|this)\s+(?:reply|response|answer|chat|message|output|conversation)\b)";

    /// <summary>An AI recipient named in content ("AI", "the assistant", "LLM"), not a person's assistant.</summary>
    public const string AiRecipient = @"(?:ai|a\.i\.|chatbots?|llms?|language\s+models?|ai\s+(?:assistants?|agents?|models?|systems?)|the\s+assistant)";

    /// <summary>Claims that would lift a check: ownership, admin rights, trust, exemption.</summary>
    public const string PrivilegeClaim =
        @"(?:owner|admin\w*|authori[sz]ed|verified|trusted|exempt|privileged|no\s+(?:\w+\s+)?(?:checks?|verification)|not\s+(?:a\s+)?secret|may\s+be\s+shared)";

    /// <summary>The end of "the instructions you were given …" when it refers to the model's own setup.</summary>
    public const string OwnSetupEnd =
        @"(?:\s*[.?!,]|\s*$|\s+(?:before|at\s+the\s+start|initially|originally|by\s+(?:your\s+)?(?:developers?|creators?|operators?|the\s+system))\b)";

    /// <summary>The end of an administrative role claim, so "an administrator of the book club" does not match.</summary>
    public const string RoleClaimEnd = @"(?:\s*[.,;:!]|\s*$|\s+(?:with|and|who|that|now)\b)";
}
