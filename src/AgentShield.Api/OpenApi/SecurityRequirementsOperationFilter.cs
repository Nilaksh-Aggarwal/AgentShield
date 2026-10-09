using AgentShield.Api.Auth;
using Microsoft.AspNetCore.Authorization;
using Microsoft.OpenApi;
using Swashbuckle.AspNetCore.SwaggerGen;

namespace AgentShield.Api.OpenApi;

/// <summary>
/// Marks every operation that is not <c>[AllowAnonymous]</c> as requiring the API key scheme (the fallback policy
/// protects all of them) and names its authorization policy in the description.
/// </summary>
internal sealed class SecurityRequirementsOperationFilter : IOperationFilter
{
    public void Apply(OpenApiOperation operation, OperationFilterContext context)
    {
        ArgumentNullException.ThrowIfNull(operation);
        ArgumentNullException.ThrowIfNull(context);

        var metadata = context.ApiDescription.ActionDescriptor.EndpointMetadata;
        if (metadata.OfType<IAllowAnonymous>().Any())
        {
            return;
        }

        operation.Security ??= [];
        operation.Security.Add(new OpenApiSecurityRequirement
        {
            [new OpenApiSecuritySchemeReference(ApiKeys.Scheme, context.Document)] = [],
        });

        var policies = metadata.OfType<IAuthorizeData>()
            .Select(data => data.Policy)
            .OfType<string>()
            .Distinct(StringComparer.Ordinal)
            .ToList();
        var requirement = policies.Count > 0
            ? $"Authorization policy: {string.Join(", ", policies)}."
            : "Authorization: any authenticated client.";
        operation.Description = string.IsNullOrEmpty(operation.Description)
            ? requirement
            : $"{operation.Description}\n\n{requirement}";
    }
}
