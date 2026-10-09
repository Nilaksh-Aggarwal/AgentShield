using System.Text.Json;
using AgentShield.Api.Http;
using AgentShield.Api.Http.Results;
using AgentShield.Application.Common.Results;
using FluentValidation;
using Microsoft.AspNetCore.Mvc;

namespace AgentShield.ApiTests.Probes;

public sealed record ProbeRequest(string? Name, int Priority, IReadOnlyList<ProbeItem>? Items);

public sealed record ProbeItem(string? DisplayName);

public sealed record ProbeResponse(string Id, string Decision);

// Explicit values so that OR-ing names is meaningful: a lenient parser reads "Block, Sanitize" as Review.
public enum ProbeDecision
{
    Allow = 0,
    Block = 1,
    Sanitize = 2,
    Review = 3,
}

/// <summary>Shape of a security request: text, an enum, nested objects and free-form JSON (e.g. tool arguments).</summary>
public sealed record ProbeEchoRequest(string? Input, ProbeDecision? Decision, IReadOnlyList<ProbeItem>? Items, JsonElement? Metadata);

public sealed class ProbeRequestValidator : AbstractValidator<ProbeRequest>
{
    public ProbeRequestValidator()
    {
        RuleFor(request => request.Name).NotEmpty();
        RuleFor(request => request.Priority).InclusiveBetween(1, 5);
        RuleForEach(request => request.Items).ChildRules(item => item.RuleFor(i => i.DisplayName).NotEmpty());
    }
}

/// <summary>Test-only endpoints that drive every Result → HTTP mapping path through the real pipeline.</summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1822:Mark members as static", Justification = "MVC actions must be instance methods; this probe has no dependencies.")]
[Route(ApiRoutes.V1 + "/__probe")]
public sealed class ContractProbeController : ApiControllerBase
{
    public const string SecretExceptionMessage = "Npgsql: password=hunter2 host=10.0.0.5 failed";

    [HttpGet("ok")]
    public IActionResult Ok200() => Result.Success(new ProbeResponse("p-1", "Block")).ToOkResult();

    [HttpPost("created")]
    [Consumes("application/json")]
    public IActionResult Created201([FromBody] ProbeRequest request) =>
        Result.Success(new ProbeResponse("p-2", request.Name!)).ToCreatedResult(value => $"/{ApiRoutes.V1}/__probe/{value.Id}");

    /// <summary>Returns the request exactly as it was parsed, so tests can see what the JSON policy accepted.</summary>
    [HttpPost("echo")]
    [Consumes("application/json")]
    public IActionResult Echo([FromBody] ProbeEchoRequest request) => Result.Success(request).ToOkResult();

    [HttpPost("accepted")]
    public IActionResult Accepted202() => Result.Success(new ProbeResponse("job-1", "Review")).ToAcceptedResult();

    [HttpDelete("no-content")]
    public IActionResult NoContent204() => Result.Success().ToNoContentResult();

    [HttpGet("failure/{type}")]
    public IActionResult Failure(ErrorType type) =>
        Result.Failure<ProbeResponse>(new Error($"Probe.{type}", $"Probe failure of type {type}.", type)).ToOkResult();

    [HttpGet("failures")]
    public IActionResult MultipleFailures() =>
        Result.Failure<ProbeResponse>(
        [
            Error.Conflict("Probe.First", "First problem."),
            Error.BusinessRule("Probe.Second", "Second problem."),
        ]).ToOkResult();

    [HttpGet("throw")]
    public IActionResult Throw() => throw new InvalidOperationException(SecretExceptionMessage);
}
