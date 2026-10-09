namespace AgentShield.Domain.Threats;

/// <summary>
/// The kind of attack a finding indicates. Each category is owned by one detector; AI-assisted analysis may report the
/// attack categories too, under its own codes.
/// </summary>
public enum ThreatCategory
{
    /// <summary>Attempts to cancel, replace or out-rank the instructions the model was given.</summary>
    InstructionOverride = 1,

    /// <summary>Attempts to change who the model believes it is or who is speaking (personas, forged roles).</summary>
    RoleManipulation = 2,

    /// <summary>Attempts to make the model disclose its instructions, credentials or other protected data.</summary>
    SecretExtraction = 3,

    /// <summary>
    /// A manipulation attempt hidden by encoding (e.g. Base64, percent or HTML-entity encoding) or by character-level
    /// disguise (look-alike letters, spaced-out letters, digit substitution), found only after undoing it.
    /// </summary>
    Obfuscation = 4,

    /// <summary>
    /// Not an attack category: part of the analysis could not complete for a reason the input itself may have caused
    /// (e.g. the AI analyser timed out, refused or answered outside its contract), so the input is held for review
    /// rather than allowed on the strength of the remaining stages.
    /// </summary>
    InconclusiveAnalysis = 5,
}
