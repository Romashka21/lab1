using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    // ===== НАДАНИЙ КОД (НЕ ЗМІНЮВАТИ): реєстрація сервісів Identity і cookie-профіль =====
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        // ===== REGISTER (етап 2, CP-01) =====
        // Request DTO: RegistrationInput (лише 4 поля). Response DTO: RegisterResponse.
        // Role, Id, PasswordHash у DTO відсутні: роль Reporter призначає сервер.
        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users) =>
        {
            // 1. Перевірка контракту (обов'язковість, довжина, формат). Пароль не нормалізуємо й не логуємо.
            var userName = input.UserName?.Trim();
            var email = input.Email?.Trim();
            var displayName = input.DisplayName?.Trim();

            var errors = new Dictionary<string, string[]>();
            if (string.IsNullOrWhiteSpace(userName) || userName.Length > 64)
                errors["userName"] = ["Ім'я користувача обов'язкове, не довше 64 символів."];
            if (string.IsNullOrWhiteSpace(email) || email.Length > 256 || !email.Contains('@'))
                errors["email"] = ["Вкажіть коректний email, не довший за 256 символів."];
            if (string.IsNullOrWhiteSpace(displayName) || displayName.Length > 120)
                errors["displayName"] = ["Відображуване ім'я обов'язкове, не довше 120 символів."];
            // Верхня межа пароля захищає від надмірно дорогого хешування (DoS).
            if (string.IsNullOrEmpty(input.Password) || input.Password.Length > 128)
                errors["password"] = ["Пароль обов'язковий, не довший за 128 символів."];
            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            // 2. Користувач створюється БЕЗ самостійного обчислення хешу: це робить UserManager.CreateAsync.
            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = userName!,
                Email = email!,
                DisplayName = displayName!
            };
            var result = await users.CreateAsync(user, input.Password!);

            // 3. Очікувані помилки Identity -> безпечні відповіді (пароль і запит у відповідь не повертаються).
            if (!result.Succeeded)
            {
                var codes = result.Errors.Select(error => error.Code).ToArray();

                // Узгоджений duplicate-контракт: 409 (усвідомлений компроміс: канал перебору акаунтів).
                if (codes.Any(code => code is "DuplicateUserName" or "DuplicateEmail"))
                    return Results.Problem(
                        statusCode: StatusCodes.Status409Conflict,
                        title: "Конфлікт реєстрації",
                        detail: "Обліковий запис з такими даними вже існує.");

                if (codes.Any(code => code.StartsWith("Password", StringComparison.Ordinal)))
                    return Results.ValidationProblem(new Dictionary<string, string[]>
                    {
                        ["password"] = ["Пароль не відповідає вимогам: щонайменше 10 символів, " +
                                        "велика й мала літери, цифра та спеціальний символ."]
                    });

                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["userName"] = ["Ім'я користувача або email мають недопустимий формат."]
                });
            }

            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");

            return Results.Created("/api/me", new RegisterResponse(user.Id, userName!, displayName!));
        });

        // ===== LOGIN (етап 3) =====
        // Для невідомого користувача й хибного пароля відповідь ОДНАКОВА (401): це A-07.
        // Подія автентифікації: лише тип, результат і trace id. Пароль, cookie, hash і тіло запиту не логуються.
        // Ім'я користувача записуємо тільки після успішного входу (у разі невдачі там може бути помилково введений пароль).
        app.MapPost("/api/auth/login", async (
            LoginInput input,
            SignInManager<ApplicationUser> signIn,
            HttpContext httpContext,
            ILogger<Program> logger) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password)
                || input.Password.Length > 128)
            {
                logger.LogInformation("Auth event {EventType}: result {Result}, trace {TraceId}",
                    "login", "failure", httpContext.TraceIdentifier);
                return Results.Unauthorized();
            }

            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);
            if (!result.Succeeded)
            {
                logger.LogInformation("Auth event {EventType}: result {Result}, trace {TraceId}",
                    "login", "failure", httpContext.TraceIdentifier);
                return Results.Unauthorized();
            }

            var safeName = input.UserName.Length > 64 ? input.UserName[..64] : input.UserName;
            logger.LogInformation("Auth event {EventType}: result {Result}, user {UserName}, trace {TraceId}",
                "login", "success", safeName, httpContext.TraceIdentifier);
            return Results.NoContent();
        }).RequireRateLimiting("login");

        // ===== LOGOUT (добрий рівень, A-06) =====
        // Стандартний sign-out Identity: у відповідь додається Set-Cookie, що видаляє основну cookie.
        app.MapPost("/api/auth/logout", async (SignInManager<ApplicationUser> signIn) =>
        {
            await signIn.SignOutAsync();
            return Results.NoContent();
        });

        // ===== /api/me (етап 3, CP-02) =====
        // Було: довіряв заголовку X-Demo-UserId (навіть без cookie). Тепер: лише verified principal.
        app.MapGet("/api/me", GetCurrentUser).RequireAuthorization();

        // Приклад лише mechanics (наданий): не повертає identity.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }

    private static IResult GetCurrentUser(HttpContext httpContext)
    {
        // Ідентифікатор і claims беруться ТІЛЬКИ з HttpContext.User (розшифрована серверна cookie).
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userId, out var verifiedUserId))
        {
            return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
        }

        var userName = httpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? string.Empty;
        var role = httpContext.User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty;

        return Results.Ok(new MeResponse(verifiedUserId, userName, role));
    }
}

// Request DTO: клієнт може передати лише ці поля.
public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);

// Response DTO: лише явно обрані безпечні поля.
public sealed record RegisterResponse(Guid Id, string UserName, string DisplayName);
public sealed record MeResponse(Guid UserId, string UserName, string Role);
