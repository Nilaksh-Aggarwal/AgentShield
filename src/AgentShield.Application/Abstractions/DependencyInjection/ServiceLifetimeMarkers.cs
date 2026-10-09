namespace AgentShield.Application.Abstractions.DependencyInjection;

// Opt-in markers for convention-based registration (Scrutor).
//
// A class that implements one of these markers is registered, with the matching lifetime, against
// every other interface it implements. Classes that need configuration, keyed registration,
// HttpClient/DbContext setup or any other special wiring must NOT use a marker — register them
// explicitly in the owning layer's DependencyInjection class instead.

/// <summary>Registers the implementing class with a scoped lifetime (one instance per request).</summary>
#pragma warning disable CA1040 // Marker interfaces are intentional: they make convention registration explicit at the class declaration.
public interface IScopedService;

/// <summary>Registers the implementing class with a transient lifetime.</summary>
public interface ITransientService;

/// <summary>Registers the implementing class with a singleton lifetime. The class must be thread-safe.</summary>
public interface ISingletonService;
#pragma warning restore CA1040
