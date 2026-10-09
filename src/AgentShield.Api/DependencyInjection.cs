using AgentShield.Api.Auth;
using AgentShield.Api.Correlation;
using AgentShield.Api.Cors;
using AgentShield.Api.ErrorHandling;
using AgentShield.Api.Health;
using AgentShield.Api.Http;
using AgentShield.Api.Logging;
using AgentShield.Api.OpenApi;
using AgentShield.Api.RateLimiting;
using AgentShield.Api.Validation;
using AgentShield.Application.Abstractions.Context;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.Options;

namespace AgentShield.Api;

internal static class DependencyInjection
{
    public static IServiceCollection AddApiPresentation(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOptions<ApiOptions>()
            .Bind(configuration.GetSection(ApiOptions.SectionName))
            .Validate(options => options.MaxRequestBodySizeBytes > 0, "Api:MaxRequestBodySizeBytes must be positive.")
            .ValidateOnStart();

        services.AddOptions<KestrelServerOptions>()
            .Configure<IOptions<ApiOptions>>((kestrel, api) =>
            {
                kestrel.Limits.MaxRequestBodySize = api.Value.MaxRequestBodySizeBytes;

                // No "Server: Kestrel" banner: the technology is nobody's business.
                kestrel.AddServerHeader = false;
            });

        services.AddSingleton(TimeProvider.System);

        // Explicit: the correlation ID lives on the HttpContext, which only the presentation layer can reach.
        services.AddHttpContextAccessor();
        services.AddSingleton<ICorrelationContext, HttpCorrelationContext>();

        // Explicit, for the same reason: the authenticated client (ID only) for use cases, and the configured client set
        // (IDs only) for the AI capacity gate's per-client shares. Neither exposes a key or a key hash.
        services.AddSingleton<ICallerContext, HttpCallerContext>();
        services.AddSingleton<IApiClientDirectory>(provider => provider.GetRequiredService<ApiClientRegistry>());

        services.AddAgentShieldLogging(configuration);

        services
            .AddControllers(options =>
            {
                options.Filters.Add<FluentValidationActionFilter>();

                // FluentValidation owns "required" rules; otherwise non-nullable properties would be
                // rejected by MVC with 400 before the validators (422) run.
                options.SuppressImplicitRequiredAttributeForNonNullableReferenceTypes = true;

                // A query or route value that does not bind (e.g. ?page=abc) is a 400 that names the field, never the
                // value: the default messages quote it ("The value 'abc' is not valid for Page."), echoing caller input.
                var messages = options.ModelBindingMessageProvider;
                messages.SetAttemptedValueIsInvalidAccessor((_, field) => $"The value is not valid for {field}.");
                messages.SetNonPropertyAttemptedValueIsInvalidAccessor(_ => "The value is not valid.");
                messages.SetValueIsInvalidAccessor(_ => "The value is not valid.");
                messages.SetValueMustNotBeNullAccessor(_ => "A value is required.");
            })
            .AddJsonOptions(options =>
            {
                JsonConventions.Apply(options.JsonSerializerOptions);

                // System.Text.Json messages name CLR types ("...could not be mapped to any .NET member contained
                // in type 'AgentShield...'"). Rejected bodies report only the JSON path and a generic message.
                options.AllowInputFormatterExceptionMessages = false;
            });

        services.ConfigureHttpJsonOptions(options => JsonConventions.Apply(options.SerializerOptions));

        services.AddProblemDetails(options => options.CustomizeProblemDetails = ProblemDetailsCustomization.Apply);
        services.AddExceptionHandler<GlobalExceptionHandler>();

        services.AddAgentShieldAuth(configuration);
        services.AddAgentShieldRateLimiting(configuration);
        services.AddAgentShieldCors(configuration);

        services.AddAgentShieldHealthChecks();
        services.AddAgentShieldSwagger();

        return services;
    }
}
