namespace AgentShield.Application.Abstractions.AiAnalysis;

/// <summary>
/// The structured output of an AI provider, exactly as received: <b>untrusted and unvalidated</b>.
/// </summary>
/// <remarks>
/// <para>Every member is nullable and enum-like values are strings on purpose: a missing field, an unknown category or
/// an out-of-range confidence must reach the central validator as data and be rejected there, identically for every
/// provider, rather than be defaulted or coerced by a serializer.</para>
/// <para>Wire format (strict JSON, see docs/security/ai-analysis.md):
/// <c>{ "findings": [ { "category", "code", "severity", "confidence", "description" } ] }</c>. There is no decision,
/// score, risk level or free-text verdict field: a security decision is never read from AI output.</para>
/// <para>Never log an instance: descriptions are model-written text that may echo the analysed input.</para>
/// </remarks>
/// <param name="Findings">Required; empty when the model found nothing.</param>
public sealed record AiAnalysisOutput(IReadOnlyList<AiFindingCandidate?>? Findings);

/// <summary>One finding as the model reported it. Untrusted until validated.</summary>
/// <param name="Category">Exact name of a <see cref="Domain.Threats.ThreatCategory"/> attack category.</param>
/// <param name="Code">A code from the AI finding catalogue that belongs to <paramref name="Category"/>.</param>
/// <param name="Severity">Exact name of a <see cref="Domain.Threats.ThreatSeverity"/>.</param>
/// <param name="Confidence">The model's own confidence, 0–1. Heuristic metadata, not a calibrated probability.</param>
/// <param name="Description">The model's short explanation. Validated but never returned, logged or stored: model-written
/// text may echo attacker-controlled input.</param>
public sealed record AiFindingCandidate(
    string? Category,
    string? Code,
    string? Severity,
    double? Confidence,
    string? Description);
