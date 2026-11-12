using Microsoft.AspNetCore.Antiforgery;

namespace SecureLab.Api.Presentation.Security;

// ЛР 6: контракт antiforgery між сервером і власним клієнтом (docs/security-review.md, розділ 8).
// Request token клієнт одержує після login з TokenRoute і повертає в HeaderName;
// cookie-частину пари браузер зберігає й надсилає сам (HttpOnly, SameSite=Strict).
public static class CsrfContract
{
    public const string HeaderName = "X-SecureLab-CSRF";
    public const string CookieName = "SecureLab.Antiforgery";
    public const string TokenRoute = "/api/auth/csrf-token";
}

public sealed record CsrfTokenResponse(string Token);

// Єдине місце валідації: ValidateRequestAsync звіряє cookie-token і request token із header
// та прив'язку до поточного principal. Відмова — завжди один і той самий 400 Problem Details,
// і handler (а отже будь-яка зміна стану) не виконується.
public sealed class AntiforgeryValidationFilter(IAntiforgery antiforgery) : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(
        EndpointFilterInvocationContext context,
        EndpointFilterDelegate next)
    {
        try
        {
            await antiforgery.ValidateRequestAsync(context.HttpContext);
        }
        catch (AntiforgeryValidationException)
        {
            return Results.Problem(
                title: "Antiforgery token відсутній або недійсний.",
                statusCode: StatusCodes.Status400BadRequest);
        }

        return await next(context);
    }
}

public static class AntiforgerySetup
{
    // Реєстрація сервісу (до builder.Build()).
    public static void AddSecureLabAntiforgery(this WebApplicationBuilder builder)
    {
        builder.Services.AddAntiforgery(options =>
        {
            options.HeaderName = CsrfContract.HeaderName;
            options.Cookie.Name = CsrfContract.CookieName;
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Strict;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest
                : CookieSecurePolicy.Always;
        });
    }

    // Один same-origin маршрут видачі. Лише для автентифікованого principal: токен прив'язаний
    // до користувача, тому після login/logout клієнт одержує новий.
    public static IEndpointRouteBuilder MapCsrfToken(this IEndpointRouteBuilder endpoints)
    {
        endpoints.MapGet(CsrfContract.TokenRoute, (IAntiforgery antiforgery, HttpContext httpContext) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(httpContext);
            return string.IsNullOrEmpty(tokens.RequestToken)
                ? Results.Problem(statusCode: StatusCodes.Status500InternalServerError)
                : Results.Ok(new CsrfTokenResponse(tokens.RequestToken));
        })
        .WithTags("Auth")
        .WithName("GetCsrfToken")
        .Produces<CsrfTokenResponse>()
        .RequireAuthorization();

        return endpoints;
    }

    // Підключення спільного filter до mutation endpoint.
    public static RouteHandlerBuilder RequireAntiforgeryToken(this RouteHandlerBuilder builder) =>
        builder.AddEndpointFilter<AntiforgeryValidationFilter>();
}
