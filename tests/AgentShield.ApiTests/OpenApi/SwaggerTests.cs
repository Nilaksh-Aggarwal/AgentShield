using System.Net;
using System.Text.Json;
using AgentShield.ApiTests.Infrastructure;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;

namespace AgentShield.ApiTests.OpenApi;

public class SwaggerTests(ApiFactory factory) : IClassFixture<ApiFactory>
{
    private static readonly string[] SwaggerPaths = ["/swagger", "/swagger/index.html", "/swagger/v1/swagger.json"];

    private readonly HttpClient _client = factory.CreateClient();

    [Fact]
    public async Task OpenApiDocument_IsServedWithApiMetadata()
    {
        var response = await _client.GetAsync("/swagger/v1/swagger.json");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var info = document.RootElement.GetProperty("info");
        Assert.Equal("AgentShield API", info.GetProperty("title").GetString());
        Assert.Equal("v1", info.GetProperty("version").GetString());
    }

    [Fact]
    public async Task OpenApiDocument_DescribesProblemDetailsForServerErrors()
    {
        var json = await _client.GetStringAsync("/swagger/v1/swagger.json");

        using var document = JsonDocument.Parse(json);
        var probe = document.RootElement.GetProperty("paths").GetProperty("/api/v1/__probe/ok").GetProperty("get");
        var serverError = probe.GetProperty("responses").GetProperty("500");

        Assert.True(serverError.GetProperty("content").TryGetProperty("application/problem+json", out _));
    }

    [Fact]
    public async Task OpenApiDocument_DescribesEnumsAsTheirDeclaredNames()
    {
        var json = await _client.GetStringAsync("/swagger/v1/swagger.json");

        using var document = JsonDocument.Parse(json);
        var schema = document.RootElement.GetProperty("components").GetProperty("schemas").GetProperty("ProbeDecision");

        Assert.Equal("string", schema.GetProperty("type").GetString());
        Assert.Equal(["Allow", "Block", "Sanitize", "Review"], schema.GetProperty("enum").EnumerateArray().Select(value => value.GetString()));
    }

    [Fact]
    public async Task OpenApiDocument_DescribesEveryRoutedControllerAction()
    {
        using var document = JsonDocument.Parse(await _client.GetStringAsync("/swagger/v1/swagger.json"));
        var paths = document.RootElement.GetProperty("paths");

        // The expectation comes from the app's own routing table, so new controllers are covered without a list here.
        var actions = factory.Services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(endpoint => endpoint.Metadata.GetMetadata<ControllerActionDescriptor>() is not null)
            .SelectMany(endpoint => endpoint.Metadata.GetRequiredMetadata<HttpMethodMetadata>().HttpMethods
                .Select(method => (Method: method, Path: "/" + endpoint.RoutePattern.RawText!.TrimStart('/'))))
            .ToList();

        Assert.Contains((HttpMethods.Post, "/api/v1/firewall/analyze"), actions);
        Assert.All(actions, action => Assert.True(
            paths.TryGetProperty(action.Path, out var item) && item.TryGetProperty(action.Method.ToLowerInvariant(), out _),
            $"{action.Method} {action.Path} is routed but missing from the OpenAPI document."));
    }

    [Fact]
    public async Task SwaggerUi_IsServedAtSwaggerRoute()
    {
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

        var redirect = await client.GetAsync("/swagger");
        Assert.Equal(HttpStatusCode.MovedPermanently, redirect.StatusCode);

        var response = await _client.GetAsync("/swagger");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("/swagger/index.html", response.RequestMessage!.RequestUri!.AbsolutePath);
        Assert.Equal("text/html", response.Content.Headers.ContentType?.MediaType);
    }

    [Fact]
    public async Task SwaggerUi_PointsAtTheV1Document()
    {
        var script = await _client.GetStringAsync("/swagger/index.js");

        Assert.Contains("/swagger/v1/swagger.json", script, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Swagger_IsEnabledInDevelopment_WithoutEnvironmentAppSettings()
    {
        // Reproduces running the API from a directory that has no appsettings*.json (e.g. the repository root):
        // Development alone must enable Swagger.
        var contentRoot = Directory.CreateTempSubdirectory("agentshield-contentroot-");
        try
        {
            using var development = factory.WithWebHostBuilder(builder => builder.UseContentRoot(contentRoot.FullName));
            using var client = development.CreateClient();

            foreach (var path in SwaggerPaths)
            {
                Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(path)).StatusCode);
            }
        }
        finally
        {
            contentRoot.Delete(recursive: true);
        }
    }

    [Fact]
    public async Task Swagger_IsDisabledInDevelopment_WhenExplicitlyDisabled()
    {
        using var development = factory.WithWebHostBuilder(builder => builder.UseSetting("Api:SwaggerEnabled", "false"));
        using var client = development.CreateClient();

        await AssertSwaggerUnavailableAsync(client);
    }

    [Fact]
    public async Task Swagger_IsDisabledOutsideDevelopment_ByDefault()
    {
        using var production = factory.WithWebHostBuilder(builder => builder.UseEnvironment("Production"));
        using var client = production.CreateClient();

        await AssertSwaggerUnavailableAsync(client);
    }

    [Fact]
    public async Task Swagger_IsEnabledOutsideDevelopment_WhenExplicitlyEnabled()
    {
        using var production = factory.WithWebHostBuilder(builder => builder
            .UseEnvironment("Production")
            .UseSetting("Api:SwaggerEnabled", "true"));
        using var client = production.CreateClient();

        foreach (var path in SwaggerPaths)
        {
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(path)).StatusCode);
        }
    }

    private static async Task AssertSwaggerUnavailableAsync(HttpClient client)
    {
        foreach (var path in SwaggerPaths)
        {
            var response = await client.GetAsync(path);

            Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        }
    }
}
