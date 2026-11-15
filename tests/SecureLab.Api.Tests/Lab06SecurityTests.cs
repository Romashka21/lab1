using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SecureLab.Api.Data;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

// ЛР 6: автоматизовані регресії hardening.
//   REG-CSRF-01 — повний сценарій: login/cookie -> відмова без токена -> незмінний стан ->
//                 видача токена -> дозволена зміна -> змінений стан (відмінний рівень);
//   REG-CSRF-02 — увесь cookie-периметр mutation без токена -> 400 і стан не змінено;
//   REG-CSRF-03 — токен іншого сеансу / анонімна видача;
//   REG-HDR-01  — F-02: заголовки безпеки й безпечний Problem Details на unexpected 500 (Production);
//   REG-ENV-01  — Production-like host: protected 4xx і змістові відмінності профілів.
// REG-RL-02 — Lab06RateLimitTests.cs; REG-F03-01 — Lab06DuplicateTitleTests.cs.
// Передумова: dotnet run --project src/SecureLab.Api -- --reset-database; SeedUsers__Password поза Git.
public sealed class Lab06SecurityTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string CsrfHeader = AntiforgeryTestExtensions.HeaderName;
    private const string TokenRoute = AntiforgeryTestExtensions.TokenRoute;
    private const string AntiforgeryRejectionTitle = "Antiforgery token відсутній або недійсний.";

    // Відкриті навчальні credentials локального стенда (README, етап 1, п. 3: accepted, study-only).
    private const string StudyConnection =
        "Host=127.0.0.1;Port=54329;Database=securelab;Username=securelab;"
        + "Password=local-study-password;Include Error Detail=false";

    // Навмисно недосяжний локальний порт для контрольованої unexpected error (етап 1, п. 5).
    private const string UnreachableConnection =
        "Host=127.0.0.1;Port=54399;Database=securelab;Username=securelab;"
        + "Password=unreachable-study-value;Include Error Detail=false";

    private static string SeedPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // Antiforgery-відмова: точний 400, Problem Details з нашим title і БЕЗ errors
    // (так вона відрізняється від validation 400 DTO).
    private static async Task AssertAntiforgeryRejectionAsync(HttpResponseMessage response)
    {
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(AntiforgeryRejectionTitle, document.RootElement.GetProperty("title").GetString());
        Assert.False(document.RootElement.TryGetProperty("errors", out _));
    }

    // ------------------------------------------------------------------ REG-CSRF-01 (відмінний: повний автоматизований)

    [Fact]
    public async Task RegCsrf01_PutWithoutToken_IsRejected_StateUnchanged_ThenValidPairChangesState()
    {
        var id = await Lab06TestData.InsertIncidentAsync(factory, DbSeeder.AliceId, "CSRF01");
        var path = Lab06TestData.IncidentPath(id);
        var newTitle = $"CSRF01-ok-{Guid.NewGuid():N}";
        try
        {
            // 1. Вхід і cookie-сеанс. Request token ще НЕ одержано.
            using var alice = await factory.LoginAsync("alice", SeedPassword);
            var before = await alice.GetFromJsonAsync<IncidentDetailsResponse>(path);
            Assert.NotNull(before);

            // 2. Відмова без токена (auth-cookie є, request token немає).
            using var rejected = await alice.PutAsJsonAsync(path,
                Lab06TestData.UpdateBody("CSRF01-changed", "Зміна без request token має бути відхилена."));
            await AssertAntiforgeryRejectionAsync(rejected);

            // 3. Читання незмінного стану.
            var afterRejected = await alice.GetFromJsonAsync<IncidentDetailsResponse>(path);
            Assert.NotNull(afterRejected);
            Assert.Equal(before.Title, afterRejected.Title);
            Assert.Equal(before.Description, afterRejected.Description);

            // 3a. Задокументоване невалідне тестове значення header -> та сама відмова, стан не змінено.
            using (var invalidRequest = new HttpRequestMessage(HttpMethod.Put, path)
            {
                Content = JsonContent.Create(Lab06TestData.UpdateBody("CSRF01-invalid", "Зміна з підробленим токеном має бути відхилена."))
            })
            {
                invalidRequest.Headers.Add(CsrfHeader, "lab06-invalid-test-value");
                using var invalid = await alice.SendAsync(invalidRequest);
                await AssertAntiforgeryRejectionAsync(invalid);
            }

            Assert.Equal(before.Title, (await Lab06TestData.StateAsync(factory, id))?.Title);

            // 4. Видача токена тією самою cookie-сесією: Set-Cookie з antiforgery cookie + токен у тілі.
            using var tokenResponse = await alice.GetAsync(TokenRoute);
            Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);
            Assert.Contains(tokenResponse.Headers.GetValues("Set-Cookie"),
                value => value.StartsWith("SecureLab.Antiforgery=", StringComparison.Ordinal));
            using var tokenJson = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());
            var token = tokenJson.RootElement.GetProperty("token").GetString();
            Assert.False(string.IsNullOrWhiteSpace(token));

            // 5. Дозволена зміна з валідною парою (cookie + header).
            using var request = new HttpRequestMessage(HttpMethod.Put, path)
            {
                Content = JsonContent.Create(Lab06TestData.UpdateBody(newTitle, "Легітимна зміна з валідною парою токенів."))
            };
            request.Headers.Add(CsrfHeader, token);
            using var accepted = await alice.SendAsync(request);
            Assert.Equal(HttpStatusCode.OK, accepted.StatusCode);

            // 6. Читання зміненого стану: саме очікувана зміна.
            var after = await alice.GetFromJsonAsync<IncidentDetailsResponse>(path);
            Assert.NotNull(after);
            Assert.Equal(newTitle, after.Title);
            Assert.Equal("Легітимна зміна з валідною парою токенів.", after.Description);
            Assert.Equal("New", after.Status);
        }
        finally
        {
            await Lab06TestData.DeleteIncidentsAsync(factory, id);
        }
    }

    // ------------------------------------------------------------------ REG-CSRF-02 (увесь периметр)

    [Fact]
    public async Task RegCsrf02_AllCookieMutations_WithoutToken_Return400_AndDoNotChangeState()
    {
        var id = await Lab06TestData.InsertIncidentAsync(factory, DbSeeder.AliceId, "CSRF02");
        var path = Lab06TestData.IncidentPath(id);
        var createTitle = $"CSRF02-create-{Guid.NewGuid():N}";
        try
        {
            using var alice = await factory.LoginAsync("alice", SeedPassword);
            using var morgan = await factory.LoginAsync("morgan", SeedPassword);
            var before = await Lab06TestData.StateAsync(factory, id);
            Assert.NotNull(before);

            using var create = await alice.PostAsJsonAsync("/api/incidents", new
            {
                title = createTitle,
                description = "Створення без request token має бути відхилене.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
            });
            using var update = await alice.PutAsJsonAsync(path,
                Lab06TestData.UpdateBody("CSRF02-changed", "Зміна без request token має бути відхилена."));
            using var delete = await alice.DeleteAsync(path);
            using var triage = await morgan.PostAsJsonAsync($"{path}/triage", new { note = "CSRF-спроба" });
            using var logout = await alice.PostAsync("/api/auth/logout", null);

            foreach (var response in new[] { create, update, delete, triage, logout })
            {
                await AssertAntiforgeryRejectionAsync(response);
            }

            // Стан не змінено: запис на місці, title/description/status ті самі, історії переходу немає,
            // нового інциденту не створено, сеанс Alice не завершено.
            Assert.Equal(before, await Lab06TestData.StateAsync(factory, id));
            Assert.False(await Lab06TestData.ExistsByTitleAsync(factory, createTitle));
            using var session = await alice.GetAsync("/api/auth/session-check");
            Assert.Equal(HttpStatusCode.NoContent, session.StatusCode);
        }
        finally
        {
            await Lab06TestData.DeleteIncidentsAsync(factory, id);
            await Lab06TestData.DeleteByTitleAsync(factory, createTitle);
        }
    }

    [Fact]
    public async Task RegCsrf04_Logout_WithoutToken_KeepsSession_WithToken_EndSession()
    {
        HttpStatusCode[] expected =
        [
            HttpStatusCode.BadRequest,
            HttpStatusCode.NoContent,
            HttpStatusCode.NoContent,
            HttpStatusCode.Unauthorized
        ];
        var trace = new List<HttpStatusCode>();
        const string AuthCookie = ".AspNetCore.Identity.Application=";
        using var alice = await factory.LoginAsync("alice", SeedPassword);
        using (var negative = await alice.PostAsync("/api/auth/logout", null))
        {
            trace.Add(negative.StatusCode);
            await AssertAntiforgeryRejectionAsync(negative);
            var cookies = negative.Headers.TryGetValues("Set-Cookie", out var values) ? values : Enumerable.Empty<string>();
            Assert.DoesNotContain(cookies, value => value.StartsWith(AuthCookie, StringComparison.Ordinal));
        }
        using (var afterNegative = await alice.GetAsync("/api/auth/session-check"))
        {
            trace.Add(afterNegative.StatusCode);
            Assert.Equal(HttpStatusCode.NoContent, afterNegative.StatusCode);

        }
        await alice.UseAntiforgeryTokenAsync();
        using (var positive = await alice.PostAsync("/api/auth/logout", null))
        {
            trace.Add(positive.StatusCode);
            Assert.Equal(HttpStatusCode.NoContent, positive.StatusCode);
            Assert.Contains(positive.Headers.GetValues("Set-Cookie"),
            value => value.StartsWith(AuthCookie, StringComparison.Ordinal));
        }
        using (var afterPositive = await alice.GetAsync("/api/auth/session-check"))
        {
            trace.Add(afterPositive.StatusCode);
            Assert.Equal(HttpStatusCode.Unauthorized, afterPositive.StatusCode);
        }
        Assert.Equal(expected, trace);
    }
    // ------------------------------------------------------------------ REG-CSRF-03 (прив'язка токена)




    [Fact]
    public async Task RegCsrf03_TokenFromAnotherSession_IsRejected_AndTokenRouteRequiresLogin()
    {
        var id = await Lab06TestData.InsertIncidentAsync(factory, DbSeeder.BobId, "CSRF03");
        var path = Lab06TestData.IncidentPath(id);
        try
        {
            using var alice = await factory.LoginWithCsrfAsync("alice", SeedPassword);
            var aliceToken = alice.DefaultRequestHeaders.GetValues(CsrfHeader).Single();

            // Bob має власну auth-cookie, але не має antiforgery cookie Alice: токен Alice для нього недійсний.
            using var bob = await factory.LoginAsync("bob", SeedPassword);
            var before = await Lab06TestData.StateAsync(factory, id);
            using var request = new HttpRequestMessage(HttpMethod.Put, path)
            {
                Content = JsonContent.Create(Lab06TestData.UpdateBody("CSRF03-changed", "Токен чужого сеансу має бути відхилений."))
            };
            request.Headers.Add(CsrfHeader, aliceToken);
            using var response = await bob.SendAsync(request);

            await AssertAntiforgeryRejectionAsync(response);
            Assert.Equal(before, await Lab06TestData.StateAsync(factory, id));

            // Анонімна видача токена не передбачена: login/register не захищаються токеном після login.
            using var anonymous = factory.CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false
            });
            using var anonymousToken = await anonymous.GetAsync(TokenRoute);
            Assert.Equal(HttpStatusCode.Unauthorized, anonymousToken.StatusCode);
        }
        finally
        {
            await Lab06TestData.DeleteIncidentsAsync(factory, id);
        }
    }

    // ------------------------------------------------------------------ REG-HDR-01 (F-02, error path)

    [Fact]
    public async Task RegHdr01_UnexpectedError_InProduction_IsSafeProblem_WithSecurityHeaders()
    {
        using var broken = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("ConnectionStrings:SecureLab", UnreachableConnection);
        });
        Assert.Equal("Production",
            broken.Services.GetRequiredService<IHostEnvironment>().EnvironmentName);

        using var client = broken.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = "NotARealPassword1!" });

        Assert.Equal(HttpStatusCode.InternalServerError, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        Assert.Contains("traceId", body, StringComparison.Ordinal);
        foreach (var forbidden in new[] { "Exception", "Npgsql", "Host=", "54399", "   at " })
        {
            Assert.DoesNotContain(forbidden, body, StringComparison.Ordinal);
        }

        // F-02: ті самі заголовки, що й на 200, є і на unexpected 500.
        Assert.Equal("nosniff", response.Headers.GetValues("X-Content-Type-Options").Single());
        Assert.Equal("no-referrer", response.Headers.GetValues("Referrer-Policy").Single());
        Assert.Contains("frame-ancestors 'none'",
            response.Headers.GetValues("Content-Security-Policy").Single(), StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------ REG-ENV-01 (Production-like host)

    [Fact]
    public async Task RegEnv01_ProductionHost_ProtectedErrorsKeep4xx_AndProfilesDiffer()
    {
        using var production = factory.WithWebHostBuilder(builder =>
        {
            builder.UseEnvironment("Production");
            builder.UseSetting("ConnectionStrings:SecureLab", StudyConnection);
        });
        Assert.Equal("Production",
            production.Services.GetRequiredService<IHostEnvironment>().EnvironmentName);

        // Клієнт: cookie-aware TestServer з https BaseAddress (поведінка застосунку, не реальний TLS).
        using var alice = await production.LoginAsync("alice", SeedPassword);
        using var allowed = await alice.GetAsync("/api/incidents");
        Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);

        using var invalid = await alice.GetAsync("/api/incidents?status=Unknown");
        Assert.Equal(HttpStatusCode.BadRequest, invalid.StatusCode);
        using (var problem = JsonDocument.Parse(await invalid.Content.ReadAsStringAsync()))
        {
            Assert.True(problem.RootElement.GetProperty("errors").TryGetProperty("status", out _));
        }

        using var missing = await alice.GetAsync("/api/incidents/99999999-9999-9999-9999-999999999999");
        Assert.Equal(HttpStatusCode.NotFound, missing.StatusCode);
        Assert.Equal("application/problem+json", missing.Content.Headers.ContentType?.MediaType);

        // Відмінності профілів: OpenAPI і CORS probe policy є лише в Development.
        using var productionOpenApi = await alice.GetAsync("/openapi/v1.json");
        Assert.Equal(HttpStatusCode.NotFound, productionOpenApi.StatusCode);
        using var developmentClient = factory.CreateClient();
        using var developmentOpenApi = await developmentClient.GetAsync("/openapi/v1.json");
        Assert.Equal(HttpStatusCode.OK, developmentOpenApi.StatusCode);

        using var corsRequest = new HttpRequestMessage(HttpMethod.Get, "/health");
        corsRequest.Headers.Add("Origin", "http://localhost:4173");
        using var cors = await alice.SendAsync(corsRequest);
        Assert.Equal(HttpStatusCode.OK, cors.StatusCode);
        Assert.False(cors.Headers.Contains("Access-Control-Allow-Origin"));
    }

}
