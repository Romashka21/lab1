using System.Globalization;
using System.Security.Claims;
using System.Threading.RateLimiting;
using Microsoft.AspNetCore.Authorization;
using SecureLab.Api.Scaffolding;
using Microsoft.EntityFrameworkCore;
using Scalar.AspNetCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Endpoints;
using SecureLab.Api.Presentation.Security;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions
{
    Args = args,
    WebRootPath = "Client"
});
builder.Services.AddOpenApi();
builder.Services.AddProblemDetails();

var connectionString = builder.Configuration.GetConnectionString("SecureLab")
    ?? throw new InvalidOperationException(
        "Connection string 'SecureLab' не налаштовано.");

builder.Services.AddDbContext<SecureLabDbContext>(options =>
    options.UseNpgsql(connectionString));
builder.Services.AddScoped<IncidentQueries>();
// ЛР 4: resource-based handler для Incident (без цього рядка AuthorizeAsync відмовлятиме всім).
builder.Services.AddSingleton<IAuthorizationHandler, IncidentAuthorizationHandler>();

builder.AddLab03Identity();

// ЛР 6: antiforgery для cookie-authenticated mutation endpoints (header X-SecureLab-CSRF).
builder.AddSecureLabAntiforgery();

// ЛР 3: обмеження частоти входів (політика "login"). Реєструється ДО builder.Build().
// Значення читаються під час запиту, тому тести можуть змінювати їх через конфігурацію.
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    // ЛР 6: узгоджений 429 для всіх policy — Problem Details + Retry-After; без імені облікового запису
    // й без деталей partition (відповідь однакова для існуючого й неіснуючого користувача).
    options.OnRejected = async (context, _) =>
    {
        if (context.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            context.HttpContext.Response.Headers.RetryAfter =
                ((int)Math.Ceiling(retryAfter.TotalSeconds)).ToString(CultureInfo.InvariantCulture);
        }

        await Results.Problem(
                title: "Забагато запитів",
                detail: "Перевищено ліміт запитів. Повторіть пізніше.",
                statusCode: StatusCodes.Status429TooManyRequests)
            .ExecuteAsync(context.HttpContext);
    };

    options.AddPolicy("login", httpContext =>
    {
        var permit = builder.Configuration.GetValue("RateLimit:Login:PermitLimit", 20);
        var window = builder.Configuration.GetValue("RateLimit:Login:WindowSeconds", 60);
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permit,
                Window = TimeSpan.FromSeconds(window),
                QueueLimit = 0
            });
    });

    // ЛР 6 (добрий/відмінний): пошук. Partition — перевірений id користувача з auth-cookie
    // (UseRateLimiter стоїть після UseAuthentication/UseAuthorization), а не IP (спільний для
    // кількох людей) і не довільний header клієнта. Анонім сюди не доходить: маршрут вимагає login.
    options.AddPolicy("search", httpContext =>
    {
        var permit = builder.Configuration.GetValue("RateLimit:Search:PermitLimit", 20);
        var window = builder.Configuration.GetValue("RateLimit:Search:WindowSeconds", 60);
        var userId = httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier);
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: userId is null ? "anonymous" : "user:" + userId,
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = permit,
                Window = TimeSpan.FromSeconds(window),
                QueueLimit = 0
            });
    });
});

// ЛР 5: навчальна CORS policy лише для Development — один exact origin probe 4173.
// 4174 навмисно не дозволено (негативний контроль). У Production policy не реєструється.
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("Lab05BrowserProbe", policy =>
        {
            policy.WithOrigins("http://localhost:4173")
                  .WithMethods("GET")
                  .WithHeaders("X-Lab-Cors-Probe")
                  .AllowCredentials();   // добрий/відмінний рівень: cookie-дослід (Етап 3, крок 5)
        });
    });
}

// Некоректний JSON дає 400, а не 500 (для перевірок register).
builder.Services.Configure<Microsoft.AspNetCore.Routing.RouteHandlerOptions>(
    options => options.ThrowOnBadRequest = false);

var app = builder.Build();

var resetRequested = args.Contains("--reset-database", StringComparer.Ordinal);
await DatabaseBootstrap.InitializeAsync(app.Services, app.Configuration, app.Environment, resetRequested);

if (resetRequested)
{
    return;
}

// ЛР 6 (F-02): заголовки безпеки ставимо через Response.OnStarting у middleware, що стоїть
// ПЕРЕД UseExceptionHandler. Раніше блок стояв після нього, і на unexpected 500 exception handler
// очищав відповідь (Response.Clear) разом із уже встановленими заголовками. OnStarting виконується
// безпосередньо перед надсиланням headers, тож охоплює й error path.
const string CspHeaderName = "Content-Security-Policy";
const string Csp =
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
    + "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

app.Use(async (context, next) =>
{
    // Виняток лише для Development-довідника Scalar (сторонній UI з власними inline-ресурсами).
    var isDevelopmentApiReference =
        app.Environment.IsDevelopment()
        && context.Request.Path.StartsWithSegments("/scalar");

    context.Response.OnStarting(() =>
    {
        var headers = context.Response.Headers;
        headers.XContentTypeOptions = "nosniff";
        headers["Referrer-Policy"] = "no-referrer";
        if (!isDevelopmentApiReference)
        {
            headers[CspHeaderName] = Csp;
        }

        return Task.CompletedTask;
    });

    await next(context);
});

app.UseExceptionHandler();
app.UseStatusCodePages();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference();
}

// ЛР 5: явний UseRouting і CORS до authentication/authorization — дозволені CORS headers є й на 401/403.
app.UseRouting();
if (app.Environment.IsDevelopment())
{
    app.UseCors("Lab05BrowserProbe");
}
app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.UseDefaultFiles();
app.UseStaticFiles();

app.MapGet("/health", async (SecureLabDbContext dbContext, CancellationToken cancellationToken) =>
    await dbContext.Database.CanConnectAsync(cancellationToken)
        ? Results.Ok(new { status = "ready" })
        : Results.Problem(
            title: "База даних недоступна",
            statusCode: StatusCodes.Status503ServiceUnavailable))
    .WithName("GetHealth")
    .Produces(StatusCodes.Status200OK)
    .ProducesProblem(StatusCodes.Status503ServiceUnavailable);

app.MapIncidentEndpoints();
app.MapCsrfToken();
app.MapLab03Identity();
app.MapLab02Endpoints();
app.MapFallbackToFile("index.html");

app.Run();

public partial class Program;