using AgentShield.Application.Abstractions.AiAnalysis;
using AgentShield.Domain.Threats;
using AgentShield.Security.AiAnalysis;
using AgentShield.Security.Detection.Obfuscation;
using AgentShield.SecurityTests.Detection;
using static AgentShield.SecurityTests.AiAnalysis.ScriptedAiSecurityAnalyzer;

namespace AgentShield.SecurityTests.AiAnalysis;

/// <summary>AI output is untrusted: every field is checked, and one violation rejects the whole response.</summary>
public class AiResponseValidatorTests
{
    private const string Provider = "TestProvider";

    [Fact]
    public void Validate_ValidFinding_MapsToCatalogueFindingWithModelSeverityAndConfidence()
    {
        var result = AiResponseValidator.Validate(Output(Candidate(severity: "Critical", confidence: 0.91)), Provider);

        var finding = Assert.Single(result.Value);
        Assert.Equal("InstructionOverride.AiDetected", finding.Code);
        Assert.Equal(ThreatCategory.InstructionOverride, finding.Category);
        Assert.Equal(ThreatSeverity.Critical, finding.Severity);
        Assert.Equal(0.91, finding.Confidence);
        Assert.Equal(AiFindingCatalog.Entries["InstructionOverride.AiDetected"].Description, finding.Description);
        Assert.Equal(new FindingEvidence("AiAnalysis", "AI/TestProvider", 1), finding.Evidence);
    }

    [Fact]
    public void Validate_ModelDescription_IsNeverCopiedIntoTheFinding()
    {
        const string marker = "zq7-echoed-user-content";

        var result = AiResponseValidator.Validate(Output(Candidate(description: $"The user wrote {marker}.")), Provider);

        var finding = Assert.Single(result.Value);
        Assert.DoesNotContain(marker, finding.Description, StringComparison.Ordinal);
        Assert.DoesNotContain(marker, finding.Code, StringComparison.Ordinal);
        Assert.DoesNotContain(finding.AllEvidence, evidence => evidence.RuleId.Contains(marker, StringComparison.Ordinal));
    }

    [Fact]
    public void Validate_EveryCatalogueCode_UnderItsOwnCategory_IsAccepted()
    {
        var candidates = AiFindingCatalog.Entries.Values
            .Select(entry => Candidate(category: entry.Category.ToString(), code: entry.Code))
            .ToArray();

        var result = AiResponseValidator.Validate(Output(candidates), Provider);

        Assert.Equal(AiFindingCatalog.Entries.Keys.Order(StringComparer.Ordinal), result.Value.Select(finding => finding.Code).Order(StringComparer.Ordinal));
    }

    [Fact]
    public void Validate_NoFindings_IsAValidAnswer()
    {
        var result = AiResponseValidator.Validate(new AiAnalysisOutput([]), Provider);

        Assert.Empty(result.Value);
    }

    [Theory]
    [InlineData(0.0)]
    [InlineData(1.0)]
    [InlineData(0.5)]
    public void Validate_ConfidenceAtOrInsideTheBounds_IsPreserved(double confidence)
    {
        var result = AiResponseValidator.Validate(Output(Candidate(confidence: confidence)), Provider);

        Assert.Equal(confidence, Assert.Single(result.Value).Confidence);
    }

    [Fact]
    public void Validate_MissingFindings_IsRejected() =>
        AssertViolation(new AiAnalysisOutput(null), "findings.required");

    [Fact]
    public void Validate_NullFindingEntry_IsRejected() =>
        AssertViolation(Output(Candidate(), null), "finding.required");

    [Fact]
    public void Validate_MaximumNumberOfFindings_IsAccepted()
    {
        var result = AiResponseValidator.Validate(Output([.. Enumerable.Repeat(Candidate(), AiAnalysisLimits.MaxFindings)]), Provider);

        Assert.Equal(AiAnalysisLimits.MaxFindings, result.Value.Count);
    }

    [Fact]
    public void Validate_MoreThanTheMaximumNumberOfFindings_IsRejectedNotTrimmed() =>
        AssertViolation(Output([.. Enumerable.Repeat(Candidate(), AiAnalysisLimits.MaxFindings + 1)]), "findings.tooMany");

    [Theory]
    [InlineData(null, "category.required")]
    [InlineData("", "category.required")]
    [InlineData("PromptInjection", "category.unknown")]
    [InlineData("instructionoverride", "category.unknown")]
    [InlineData("INSTRUCTIONOVERRIDE", "category.unknown")]
    [InlineData(" InstructionOverride", "category.unknown")]
    [InlineData("1", "category.unknown")]
    [InlineData("InstructionOverride, RoleManipulation", "category.unknown")]
    [InlineData("InconclusiveAnalysis", "category.unknown")]
    public void Validate_CategoryThatIsNotAnExactAttackCategoryName_IsRejected(string? category, string violation) =>
        AssertViolation(Output(Candidate(category: category)), violation);

    [Theory]
    [InlineData(null, "code.required")]
    [InlineData("", "code.required")]
    [InlineData("PROMPT_INJECTION", "code.unknown")]
    [InlineData("instructionoverride.aidetected", "code.unknown")]
    [InlineData("InconclusiveAnalysis.AiAnalysisIncomplete", "code.unknown")]
    public void Validate_CodeOutsideTheCatalogue_IsRejected(string? code, string violation) =>
        AssertViolation(Output(Candidate(code: code)), violation);

    [Fact]
    public void Validate_CodeReportedUnderAnotherCategory_IsRejected() =>
        AssertViolation(Output(Candidate(category: "SecretExtraction", code: "InstructionOverride.AiDetected")), "code.categoryMismatch");

    [Fact]
    public void Validate_DeterministicRuleCodes_CannotBeClaimedByTheAi()
    {
        // If the AI could report a detector's code, its finding would be fused into (and could masquerade as) the
        // deterministic one. Every detector code must be rejected.
        (string Code, ThreatCategory Category)[] obfuscationCodes =
        [
            (ObfuscationDetector.EncodedThreatCode, ThreatCategory.Obfuscation),
            (ObfuscationDetector.MaskedThreatCode, ThreatCategory.Obfuscation),
            (ObfuscationDetector.UninspectableContentCode, ThreatCategory.Obfuscation),
        ];
        var detectorCodes = DetectorHarness.AllDetectors()
            .SelectMany(detector => detector.Rules.Select(rule => (rule.Code, Category: Enum.Parse<ThreatCategory>(detector.DetectorId))))
            .Concat(obfuscationCodes)
            .Distinct()
            .ToArray();
        Assert.Equal(25, detectorCodes.Length);

        Assert.All(detectorCodes, pair =>
            AssertViolation(Output(Candidate(category: pair.Category.ToString(), code: pair.Code)), "code.unknown"));
    }

    [Theory]
    [InlineData(null, "severity.required")]
    [InlineData("", "severity.required")]
    [InlineData("high", "severity.unknown")]
    [InlineData("HIGH", "severity.unknown")]
    [InlineData("3", "severity.unknown")]
    [InlineData("Severe", "severity.unknown")]
    [InlineData("None", "severity.unknown")]
    public void Validate_SeverityThatIsNotAnExactSeverityName_IsRejected(string? severity, string violation) =>
        AssertViolation(Output(Candidate(severity: severity)), violation);

    [Theory]
    [InlineData(-0.01)]
    [InlineData(1.01)]
    [InlineData(91.0)]
    [InlineData(double.NaN)]
    [InlineData(double.PositiveInfinity)]
    [InlineData(double.NegativeInfinity)]
    public void Validate_ConfidenceOutsideZeroToOne_IsRejected(double confidence) =>
        AssertViolation(Output(Candidate(confidence: confidence)), "confidence.outOfRange");

    [Fact]
    public void Validate_MissingConfidence_IsRejected() =>
        AssertViolation(Output(Candidate(confidence: null)), "confidence.required");

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Validate_MissingDescription_IsRejected(string? description) =>
        AssertViolation(Output(Candidate(description: description)), "description.required");

    [Fact]
    public void Validate_DescriptionAtTheLengthLimit_IsAccepted()
    {
        var result = AiResponseValidator.Validate(Output(Candidate(description: new string('a', AiAnalysisLimits.MaxDescriptionLength))), Provider);

        Assert.True(result.IsSuccess);
    }

    [Fact]
    public void Validate_DescriptionOverTheLengthLimit_IsRejected() =>
        AssertViolation(Output(Candidate(description: new string('a', AiAnalysisLimits.MaxDescriptionLength + 1))), "description.tooLong");

    [Fact]
    public void Validate_OneInvalidFindingAmongValidOnes_RejectsTheWholeResponse()
    {
        // A Critical finding next to a broken one is not salvaged: a response that breaks the contract anywhere is not
        // trusted anywhere.
        var output = Output(Candidate(severity: "Critical"), Candidate(confidence: 7), Candidate(code: "SecretExtraction.AiDetected", category: "SecretExtraction"));

        AssertViolation(output, "confidence.outOfRange");
    }

    [Fact]
    public void Validate_Failure_IsAnExternalDependencyErrorWithAFixedMessage()
    {
        var result = AiResponseValidator.Validate(Output(Candidate(description: "x", severity: "bogus-zq7")), Provider);

        Assert.Equal(AiResponseValidator.InvalidResponseCode, result.Error.Code);
        Assert.Equal(Application.Common.Results.ErrorType.ExternalDependency, result.Error.Type);
        Assert.DoesNotContain("zq7", result.Error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain(result.Error.Metadata.Values, value => value is string text && text.Contains("zq7", StringComparison.Ordinal));
    }

    private static AiAnalysisOutput Output(params AiFindingCandidate?[] findings) => new(findings);

    private static void AssertViolation(AiAnalysisOutput output, string violation)
    {
        var result = AiResponseValidator.Validate(output, Provider);

        Assert.True(result.IsFailure, $"Expected {violation}.");
        Assert.Equal(violation, result.Error.Metadata[AiResponseValidator.ViolationKey]);
    }
}
