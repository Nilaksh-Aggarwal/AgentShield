using System.Net;
using System.Net.Http.Json;
using System.Text;
using AgentShield.Api.Http.Results;
using AgentShield.ApiTests.Infrastructure;
using AgentShield.ApiTests.Probes;
using AgentShield.Application.Common.Results;

namespace AgentShield.ApiTests.Http;

public class ErrorResponseContractTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    [Theory]
    [InlineData(ErrorType.Validation, HttpStatusCode.UnprocessableEntity)]
    [InlineData(ErrorType.BusinessRule, HttpStatusCode.UnprocessableEntity)]
    [InlineData(ErrorType.NotFound, HttpStatusCode.NotFound)]
    [InlineData(ErrorType.Conflict, HttpStatusCode.Conflict)]
    [InlineData(ErrorType.Unauthorized, HttpStatusCode.Unauthorized)]
    [InlineData(ErrorType.Forbidden, HttpStatusCode.Forbidden)]
    [InlineData(ErrorType.ExternalDependency, HttpStatusCode.BadGateway)]
    [InlineData(ErrorType.Unexpected, HttpStatusCode.InternalServerError)]
    public void ErrorStatusCodes_MapEveryErrorType(ErrorType type, HttpStatusCode expected)
    {
        Assert.Equal((int)expected, ErrorStatusCodes.For(type));
    }

    [Fact]
    public void ErrorStatusCodes_CoverEveryDefinedErrorType()
    {
        foreach (var type in Enum.GetValues<ErrorType>())
        {
            var status = ErrorStatusCodes.For(type);
            Assert.InRange(status, 400, 599);
        }
    }

    [Theory]
    [InlineData(ErrorType.NotFound, HttpStatusCode.NotFound)]
    [InlineData(ErrorType.Conflict, HttpStatusCode.Conflict)]
    [InlineData(ErrorType.BusinessRule, HttpStatusCode.UnprocessableEntity)]
    [InlineData(ErrorType.Forbidden, HttpStatusCode.Forbidden)]
    [InlineData(ErrorType.ExternalDependency, HttpStatusCode.BadGateway)]
    public async Task FailedResult_IsProblemDetailsWithErrorCodeAndMessage(ErrorType type, HttpStatusCode expected)
    {
        var response = await _client.GetAsync($"/api/v1/__probe/failure/{type}");

        var problem = await ProblemAssertions.AssertProblemAsync(response, expected, $"Probe.{type}");
        Assert.Equal($"Probe failure of type {type}.", problem.GetProperty("detail").GetString());
    }

    [Fact]
    public async Task FailedResult_WithSeveralErrors_UsesFirstForStatusAndListsAll()
    {
        var response = await _client.GetAsync("/api/v1/__probe/failures");

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.Conflict, "Probe.First");
        var errors = problem.GetProperty("errors").EnumerateArray().Select(e => e.GetProperty("code").GetString()!).ToArray();
        Assert.Equal(["Probe.First", "Probe.Second"], errors);
    }

    [Fact]
    public async Task InvalidRequest_Returns422WithCamelCaseFieldErrors()
    {
        var response = await _client.PostAsJsonAsync(
            "/api/v1/__probe/created",
            new { name = "", priority = 9, items = new[] { new { displayName = "" } } });

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.UnprocessableEntity, "Validation.Failed");
        var errors = problem.GetProperty("errors");
        Assert.True(errors.TryGetProperty("name", out _));
        Assert.True(errors.TryGetProperty("priority", out _));
        Assert.True(errors.TryGetProperty("items[0].displayName", out _));
    }

    [Fact]
    public async Task MissingRequiredField_IsValidatedByFluentValidation_NotRejectedByModelBinding()
    {
        var response = await _client.PostAsJsonAsync("/api/v1/__probe/created", new { priority = 1 });

        var problem = await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.UnprocessableEntity, "Validation.Failed");
        Assert.True(problem.GetProperty("errors").TryGetProperty("name", out _));
    }

    [Fact]
    public async Task MalformedJson_Returns400()
    {
        using var content = new StringContent("{ \"name\": ", Encoding.UTF8, "application/json");

        var response = await _client.PostAsync("/api/v1/__probe/created", content);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.BadRequest, "Request.Malformed");
    }

    [Fact]
    public async Task NumberSentAsString_IsRejectedAsMalformed()
    {
        using var content = new StringContent("{ \"name\": \"x\", \"priority\": \"1\" }", Encoding.UTF8, "application/json");

        var response = await _client.PostAsync("/api/v1/__probe/created", content);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.BadRequest, "Request.Malformed");
    }

    [Fact]
    public async Task UnsupportedContentType_Returns415()
    {
        using var content = new StringContent("name=x", Encoding.UTF8, "text/plain");

        var response = await _client.PostAsync("/api/v1/__probe/created", content);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.UnsupportedMediaType, "Request.UnsupportedMediaType");
    }

    [Fact]
    public async Task UnknownRoute_Returns404ProblemDetails()
    {
        var response = await _client.GetAsync("/api/v1/does-not-exist");

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.NotFound, "Resource.NotFound");
    }

    [Fact]
    public async Task WrongMethod_Returns405ProblemDetails()
    {
        var response = await _client.PutAsync("/api/v1/__probe/ok", content: null);

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.MethodNotAllowed, "Request.MethodNotAllowed");
    }

    [Fact]
    public async Task UnhandledException_Returns500WithoutLeakingInternals()
    {
        var response = await _client.GetAsync("/api/v1/__probe/throw");

        await ProblemAssertions.AssertProblemAsync(response, HttpStatusCode.InternalServerError, "Server.Unexpected");

        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("hunter2", body, StringComparison.Ordinal);
        Assert.DoesNotContain("Npgsql", body, StringComparison.Ordinal);
        Assert.DoesNotContain(nameof(InvalidOperationException), body, StringComparison.Ordinal);
        Assert.DoesNotContain(nameof(ContractProbeController), body, StringComparison.Ordinal);
        Assert.DoesNotContain(" at ", body, StringComparison.Ordinal);
    }
}
