namespace AgentShield.Application.Abstractions.Security;

/// <summary>
/// Produces the canonical form of untrusted input that every detector analyses. Deterministic and side-effect free.
/// </summary>
/// <remarks>
/// Also applied by detectors to content they derive from the input (e.g. text decoded from Base64), so derived content
/// is inspected in the same canonical form.
/// </remarks>
public interface IInputNormalizer
{
    NormalizedInput Normalize(string input);
}

/// <summary>Untrusted input in two forms: exactly as received, and canonicalised for analysis.</summary>
/// <remarks>
/// A third form, content a detector derives by decoding or unmasking the normalised text, or by reading text hidden in
/// invisible characters of the original that normalisation removes, exists only inside that detector for the duration
/// of the call. It is never stored here, put in a finding, logged or returned.
/// </remarks>
/// <param name="Original">
/// The input exactly as received. Kept for audit context and for detectors that inspect what normalisation removes;
/// never logged.
/// </param>
/// <param name="Normalized">The canonical form detectors analyse. Never sent onwards in place of the original.</param>
public sealed record NormalizedInput(string Original, string Normalized);
