namespace AgentShield.Api;

/// <summary>Presentation-layer settings (section <c>Api</c>).</summary>
public sealed class ApiOptions
{
    public const string SectionName = "Api";

    /// <summary>
    /// Serve the OpenAPI document and Swagger UI. Unset (the default) means "only in the Development environment";
    /// an explicit value overrides the environment in either direction. The default comes from the environment,
    /// not from appsettings.Development.json, so Development keeps Swagger whatever the content root is.
    /// </summary>
    public bool? SwaggerEnabled { get; set; }

    /// <summary>Maximum accepted request body (Kestrel). Larger requests receive 413.</summary>
    public long MaxRequestBodySizeBytes { get; set; } = 1_048_576;

    public bool IsSwaggerEnabled(IHostEnvironment environment) => SwaggerEnabled ?? environment.IsDevelopment();
}
