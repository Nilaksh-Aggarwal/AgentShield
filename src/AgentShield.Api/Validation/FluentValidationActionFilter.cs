using AgentShield.Api.Http.Results;
using AgentShield.Application.Common.Results;
using AgentShield.Application.Common.Validation;
using FluentValidation;
using Microsoft.AspNetCore.Mvc.Filters;

namespace AgentShield.Api.Validation;

/// <summary>
/// Runs every registered <see cref="IValidator{T}"/> for each bound action argument before the action
/// executes. Failures short-circuit with 422 Problem Details; the use case never sees invalid input.
/// </summary>
/// <remarks>
/// Validators are declared in the Application layer next to the request they validate and registered by
/// <c>AddApplication()</c>. The validator type depends on the runtime argument type, so it is resolved
/// from the request's service provider — this filter is framework glue, not a pattern for application code.
/// </remarks>
internal sealed class FluentValidationActionFilter : IAsyncActionFilter
{
    public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(next);

        var services = context.HttpContext.RequestServices;
        var cancellationToken = context.HttpContext.RequestAborted;
        List<Error>? errors = null;

        foreach (var argument in context.ActionArguments.Values)
        {
            if (argument is null)
            {
                continue;
            }

            var validatorType = typeof(IValidator<>).MakeGenericType(argument.GetType());
            foreach (var validator in services.GetServices(validatorType).OfType<IValidator>())
            {
                var result = await validator.ValidateAsync(new ValidationContext<object>(argument), cancellationToken);
                if (!result.IsValid)
                {
                    (errors ??= []).AddRange(result.ToErrors());
                }
            }
        }

        if (errors is not null)
        {
            context.Result = errors.ToProblemResult();
            return;
        }

        await next();
    }
}
