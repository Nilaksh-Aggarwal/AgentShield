using AgentShield.Api.Auth;
using Microsoft.OpenApi;

namespace AgentShield.Api.OpenApi;

internal static class SwaggerSetup
{
    public const string DocumentName = "v1";

    public static IServiceCollection AddAgentShieldSwagger(this IServiceCollection services)
    {
        services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc(DocumentName, new OpenApiInfo
            {
                Title = "AgentShield API",
                Version = DocumentName,
                Description =
                    "AI security firewall for agentic systems. Successful responses use the { data, meta } envelope; " +
                    "errors are RFC 9457 Problem Details (application/problem+json) carrying correlationId, timestamp " +
                    "and errorCode. Every response echoes the X-Correlation-ID header.",
            });

            var xmlFile = Path.Combine(AppContext.BaseDirectory, $"{typeof(Program).Assembly.GetName().Name}.xml");
            if (File.Exists(xmlFile))
            {
                options.IncludeXmlComments(xmlFile, includeControllerXmlComments: true);
            }

            options.SupportNonNullableReferenceTypes();

            // Query parameters bound from a request type (GET /api/v1/activity) are documented as clients write them, in
            // camelCase like every JSON member; binding itself matches names case-insensitively.
            options.DescribeAllParametersInCamelCase();

            // Documents the scheme only: no key value, example or default is ever part of the document.
            options.AddSecurityDefinition(ApiKeys.Scheme, new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.ApiKey,
                In = ParameterLocation.Header,
                Name = ApiKeys.HeaderName,
                Description =
                    $"API key issued to the calling client, sent in the {ApiKeys.HeaderName} header. Missing or invalid → 401; " +
                    "valid but without the endpoint's permission → 403. Development only: the public development key " +
                    "listed in the README works in the Development environment and is rejected at startup anywhere else.",
            });
            options.OperationFilter<SecurityRequirementsOperationFilter>();
        });

        return services;
    }

    public static WebApplication UseAgentShieldSwagger(this WebApplication app)
    {
        app.UseSwagger();
        app.UseSwaggerUI(options =>
        {
            options.SwaggerEndpoint($"/swagger/{DocumentName}/swagger.json", "AgentShield API v1");
            options.RoutePrefix = "swagger";
            options.DocumentTitle = "AgentShield API";
        });

        return app;
    }
}
