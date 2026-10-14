using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

// ЛР 3: A-01…A-07, duplicate, cookie flags, rate limit + поглиблення (rehash, security stamp).
// Паролі акаунтів seed беруться зі змінної середовища SeedUsers__Password; нові паролі генеруються під час запуску.
public sealed class Lab03SecurityTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string CookieName = ".AspNetCore.Identity.Application=";

    private static string SeedPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    // Генерований одноразовий пароль, що відповідає політиці: >=10 символів, велика, мала, цифра, символ.
    private static string NewPassword() => "Aa1-" + Guid.NewGuid().ToString("N");

    private static HttpClient NewClient(WebApplicationFactory<Program> host, bool https = true) =>
        host.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri(https ? "https://localhost" : "http://localhost"),
            AllowAutoRedirect = false,
            HandleCookies = true
        });

    private static object IncidentBody(string title, object? extra = null)
    {
        var body = new Dictionary<string, object?>
        {
            ["title"] = title,
            ["description"] = "Штучний запис для автоматичного тесту.",
            ["severity"] = "Low",
            ["occurredAtUtc"] = DateTimeOffset.UtcNow.AddMinutes(-10)
        };
        if (extra is IDictionary<string, object?> more)
            foreach (var pair in more) body[pair.Key] = pair.Value;
        return body;
    }

    private static async Task DeleteIncidentByTitleAsync(WebApplicationFactory<Program> host, string title)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
    }

    private static async Task DeleteUserAsync(WebApplicationFactory<Program> host, string userName)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await users.FindByNameAsync(userName);
        if (user is not null) await users.DeleteAsync(user);
    }

    private static void AssertNoSensitiveProperties(JsonElement root)
    {
        string[] forbidden = ["password", "confirmpassword", "passwordhash", "securitystamp",
            "concurrencystamp", "token", "cookie"];
        foreach (var property in root.EnumerateObject())
            Assert.DoesNotContain(property.Name.ToLowerInvariant(), forbidden);
    }

    // Стабільні поля Problem Details (traceId навмисно НЕ порівнюємо).
    private static async Task<(int Status, string? ContentType, string Fields)> StableShapeAsync(HttpResponseMessage reply)
    {
        var body = await reply.Content.ReadAsStringAsync();
        var fields = "";
        if (!string.IsNullOrWhiteSpace(body))
        {
            using var document = JsonDocument.Parse(body);
            var root = document.RootElement;
            string Field(string name) => root.TryGetProperty(name, out var value) ? value.ToString() : "<absent>";
            fields = $"{Field("type")}|{Field("title")}|{Field("status")}|{Field("detail")}";
        }
        return ((int)reply.StatusCode, reply.Content.Headers.ContentType?.MediaType, fields);
    }

    // ---------------------------------------------------------------- T-01 / T-02 (автоматизовано для «Добре»)

    [Fact]
    public async Task T01_Register_Valid_Returns201_WithOnlySafeFields()
    {
        var userName = "reg" + Guid.NewGuid().ToString("N")[..8];
        try
        {
            using var client = NewClient(factory);
            using var response = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName, email = userName + "@example.test", displayName = "Студент", password = NewPassword()
            });

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            AssertNoSensitiveProperties(json.RootElement);
            Assert.Equal(new[] { "displayName", "id", "userName" },
                json.RootElement.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal));
        }
        finally { await DeleteUserAsync(factory, userName); }
    }

    [Fact]
    public async Task T02_Register_WeakPassword_Returns400_WithoutEchoAndWithoutAccount()
    {
        var userName = "weak" + Guid.NewGuid().ToString("N")[..8];
        const string weak = "short1!";
        try
        {
            using var client = NewClient(factory);
            using var response = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName, email = userName + "@example.test", displayName = "Студент", password = weak
            });

            Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
            Assert.DoesNotContain(weak, await response.Content.ReadAsStringAsync());

            await using var scope = factory.Services.CreateAsyncScope();
            var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
            Assert.Null(await users.FindByNameAsync(userName));
        }
        finally { await DeleteUserAsync(factory, userName); }
    }

    [Fact]
    public async Task T02_Register_MissingFieldsAndLongDisplayName_Return400()
    {
        using var client = NewClient(factory);
        using var missing = await client.PostAsJsonAsync("/api/auth/register", new { userName = "x" });
        Assert.Equal(HttpStatusCode.BadRequest, missing.StatusCode);

        var userName = "long" + Guid.NewGuid().ToString("N")[..8];
        try
        {
            using var tooLong = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName, email = userName + "@example.test",
                displayName = new string('d', 121), password = NewPassword()
            });
            Assert.Equal(HttpStatusCode.BadRequest, tooLong.StatusCode);
        }
        finally { await DeleteUserAsync(factory, userName); }
    }

    [Fact]
    public async Task T02_Register_ExtraRoleAndIdFields_AreIgnored_UserStaysReporter()
    {
        var userName = "extra" + Guid.NewGuid().ToString("N")[..8];
        var password = NewPassword();
        var sentId = Guid.Parse("99999999-9999-9999-9999-999999999999");
        try
        {
            using var client = NewClient(factory);
            using var register = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName, email = userName + "@example.test", displayName = "Студент", password,
                role = "Administrator", id = sentId
            });
            Assert.Equal(HttpStatusCode.Created, register.StatusCode);

            using var user = await factory.LoginAsync(userName, password);
            using var me = await user.GetAsync("/api/me");
            using var json = JsonDocument.Parse(await me.Content.ReadAsStringAsync());
            Assert.Equal("Reporter", json.RootElement.GetProperty("role").GetString());
            Assert.NotEqual(sentId, json.RootElement.GetProperty("userId").GetGuid());
        }
        finally { await DeleteUserAsync(factory, userName); }
    }

    [Fact]
    public async Task Duplicate_Register_SameUserNameOrEmail_Returns409_Consistently()
    {
        var first = "dup" + Guid.NewGuid().ToString("N")[..8];
        var second = "dup" + Guid.NewGuid().ToString("N")[..8];
        try
        {
            using var client = NewClient(factory);
            using var created = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName = first, email = first + "@example.test", displayName = "Студент", password = NewPassword()
            });
            Assert.Equal(HttpStatusCode.Created, created.StatusCode);

            using var sameUserName = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName = first, email = second + "@example.test", displayName = "Студент", password = NewPassword()
            });
            using var sameEmail = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName = second, email = first + "@example.test", displayName = "Студент", password = NewPassword()
            });

            Assert.Equal(HttpStatusCode.Conflict, sameUserName.StatusCode);
            Assert.Equal(HttpStatusCode.Conflict, sameEmail.StatusCode);
            Assert.Equal(await StableShapeAsync(sameUserName), await StableShapeAsync(sameEmail));
        }
        finally
        {
            await DeleteUserAsync(factory, first);
            await DeleteUserAsync(factory, second);
        }
    }

    // ---------------------------------------------------------------- A-01 … A-07

    [Fact]
    public async Task A01_Anonymous_ProtectedEndpoints_Return401_NotRedirect_NotHtml()
    {
        var title = $"A01-{Guid.NewGuid():N}";
        try
        {
            using var anonymous = NewClient(factory);
            using var create = await anonymous.PostAsJsonAsync("/api/incidents", IncidentBody(title));
            using var me = await anonymous.GetAsync("/api/me");

            foreach (var response in new[] { create, me })
            {
                Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
                Assert.Null(response.Headers.Location);
                Assert.Empty(response.Headers.WwwAuthenticate);
                Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
            }

            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            Assert.False(await db.Incidents.AnyAsync(item => item.Title == title));
        }
        finally { await DeleteIncidentByTitleAsync(factory, title); }
    }

    [Fact]
    public async Task A02_Login_ThenMe_ReturnsVerifiedPrincipal_WithSafeFields()
    {
        using var alice = await factory.LoginAsync("alice", SeedPassword);
        using var response = await alice.GetAsync("/api/me");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = json.RootElement;
        Assert.Equal(DbSeeder.AliceId, root.GetProperty("userId").GetGuid());
        Assert.Equal("alice", root.GetProperty("userName").GetString());
        Assert.Equal("Reporter", root.GetProperty("role").GetString());
        AssertNoSensitiveProperties(root);
        Assert.Equal(new[] { "role", "userId", "userName" },
            root.EnumerateObject().Select(p => p.Name).OrderBy(n => n, StringComparer.Ordinal));
    }

    [Fact]
    public async Task A03_ForgedDemoUserIdHeader_DoesNotChangeMe()
    {
        using var alice = await factory.LoginAsync("alice", SeedPassword);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/me");
        request.Headers.Add("X-Demo-UserId", DbSeeder.BobId.ToString());

        using var response = await alice.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceId, json.RootElement.GetProperty("userId").GetGuid());
    }

    [Fact]
    public async Task A04_Create_WithoutOwnerInDto_OwnerIsPrincipal()
    {
        var title = $"A04-{Guid.NewGuid():N}";
        try
        {
            using var bob = await factory.LoginAsync("bob", SeedPassword);
            using var response = await bob.PostAsJsonAsync("/api/incidents", IncidentBody(title));

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            var created = await response.Content.ReadFromJsonAsync<CreatedIncidentResponse>();
            Assert.NotNull(created);
            Assert.Equal(DbSeeder.BobId, await OwnerOfAsync(created.Id));
        }
        finally { await DeleteIncidentByTitleAsync(factory, title); }
    }

    [Fact]
    public async Task A05_Create_WithForgedOwnerInJson_OwnerStaysPrincipal()
    {
        var title = $"A05-{Guid.NewGuid():N}";
        try
        {
            using var bob = await factory.LoginAsync("bob", SeedPassword);
            var forged = new Dictionary<string, object?> { ["ownerUserId"] = DbSeeder.AliceId };
            using var response = await bob.PostAsJsonAsync("/api/incidents", IncidentBody(title, forged));

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            var created = await response.Content.ReadFromJsonAsync<CreatedIncidentResponse>();
            Assert.NotNull(created);
            var owner = await OwnerOfAsync(created.Id);
            Assert.Equal(DbSeeder.BobId, owner);
            Assert.NotEqual(DbSeeder.AliceId, owner);
        }
        finally { await DeleteIncidentByTitleAsync(factory, title); }
    }

    private async Task<Guid> OwnerOfAsync(Guid incidentId)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.AsNoTracking().SingleAsync(item => item.Id == incidentId);
        return incident.OwnerUserId;
    }

    [Fact]
    public async Task A06_Logout_ThenProtectedRequest_Returns401()
    {
        using var alice = await factory.LoginAsync("alice", SeedPassword);
        using (var before = await alice.GetAsync("/api/auth/session-check"))
            Assert.Equal(HttpStatusCode.NoContent, before.StatusCode);

        using var logout = await alice.PostAsync("/api/auth/logout", null);
        Assert.Equal(HttpStatusCode.NoContent, logout.StatusCode);
        // Основна cookie присутня у Set-Cookie (з порожнім значенням і датою в минулому); значення не читаємо.
        Assert.Contains(logout.Headers.GetValues("Set-Cookie"),
            value => value.StartsWith(CookieName, StringComparison.Ordinal));

        using var after = await alice.GetAsync("/api/auth/session-check");
        using var meAfter = await alice.GetAsync("/api/me");
        Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, meAfter.StatusCode);
    }

    [Fact]
    public async Task A07_UnknownUser_And_WrongPassword_HaveIdenticalExternalResult()
    {
        using var client = NewClient(factory);
        using var unknown = await client.PostAsJsonAsync("/api/auth/login", new
        {
            userName = "nobody" + Guid.NewGuid().ToString("N")[..8], password = NewPassword()
        });
        using var wrong = await client.PostAsJsonAsync("/api/auth/login", new
        {
            userName = "alice", password = NewPassword()
        });

        Assert.Equal(HttpStatusCode.Unauthorized, unknown.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, wrong.StatusCode);
        Assert.Equal(await StableShapeAsync(unknown), await StableShapeAsync(wrong));
        Assert.Empty(unknown.Headers.WwwAuthenticate);
        Assert.Empty(wrong.Headers.WwwAuthenticate);
        Assert.False(unknown.Headers.Contains("Set-Cookie"));
        Assert.False(wrong.Headers.Contains("Set-Cookie"));
    }

    // ---------------------------------------------------------------- cookie flags (добрий рівень)

    [Fact]
    public async Task Cookie_Flags_Https_HttpOnlySecureLax_Http_NoSecure()
    {
        var https = await LoginCookieAttributesAsync(useHttps: true);
        Assert.Contains("httponly", https);
        Assert.Contains("secure", https);
        Assert.Contains("samesite=lax", https);
        Assert.Contains("path=/", https);

        // Межа локального HTTP: у Development (SameAsRequest) за HTTP атрибута secure немає.
        var http = await LoginCookieAttributesAsync(useHttps: false);
        Assert.Contains("httponly", http);
        Assert.Contains("samesite=lax", http);
        Assert.DoesNotContain("secure", http);
    }

    private async Task<string[]> LoginCookieAttributesAsync(bool useHttps)
    {
        using var client = NewClient(factory, useHttps);
        using var response = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = SeedPassword });
        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);

        var matching = response.Headers.GetValues("Set-Cookie")
            .Where(value => value.StartsWith(CookieName, StringComparison.Ordinal)).ToArray();
        Assert.True(matching.Length == 1);   // за кількістю: значення cookie не потрапляє у повідомлення помилки
        return matching[0].Split(';').Skip(1).Select(part => part.Trim().ToLowerInvariant()).ToArray();
    }

    // ---------------------------------------------------------------- rate limit (добрий рівень)

    [Fact]
    public async Task RateLimit_Login_Returns429_ThenRecovers_AndDoesNotRevealAccounts()
    {
        // Окремий host: лічильники належать host, тому інші тести квоту не вичерпують.
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["RateLimit:Login:PermitLimit"] = "3",
                    ["RateLimit:Login:WindowSeconds"] = "4"
                })));
        using var client = NewClient(host);

        for (var attempt = 0; attempt < 3; attempt++)
        {
            using var failed = await client.PostAsJsonAsync("/api/auth/login",
                new { userName = "alice", password = NewPassword() });
            Assert.Equal(HttpStatusCode.Unauthorized, failed.StatusCode);
        }

        using var limitedKnown = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = NewPassword() });
        using var limitedUnknown = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "nobody" + Guid.NewGuid().ToString("N")[..8], password = NewPassword() });

        Assert.Equal(HttpStatusCode.TooManyRequests, limitedKnown.StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, limitedUnknown.StatusCode);
        // 429 однаковий для існуючого й неіснуючого облікового запису.
        Assert.Equal(await StableShapeAsync(limitedKnown), await StableShapeAsync(limitedUnknown));

        await Task.Delay(TimeSpan.FromSeconds(4.5));   // вікно + запас

        using var recovered = await client.PostAsJsonAsync("/api/auth/login",
            new { userName = "alice", password = SeedPassword });
        Assert.Equal(HttpStatusCode.NoContent, recovered.StatusCode);
    }

    // ---------------------------------------------------------------- ПОГЛИБЛЕННЯ (відмінний рівень)

    // Поглиблення «готовність до оновлення хешу»: стандартний hasher читає старий формат
    // і повертає SuccessRehashNeeded; сіль робить хеші одного пароля різними. Хеш не друкується.
    [Fact]
    public void Deepening_PasswordHasher_OldIterationCount_RequestsRehash()
    {
        var password = NewPassword();
        var user = new ApplicationUser { DisplayName = "Hasher Probe" };
        var oldHasher = new PasswordHasher<ApplicationUser>(
            Options.Create(new PasswordHasherOptions { IterationCount = 10_000 }));
        var currentHasher = new PasswordHasher<ApplicationUser>();   // стандартні параметри (100 000)

        var oldHash = oldHasher.HashPassword(user, password);

        Assert.Equal(PasswordVerificationResult.SuccessRehashNeeded,
            currentHasher.VerifyHashedPassword(user, oldHash, password));
        Assert.Equal(PasswordVerificationResult.Failed,
            currentHasher.VerifyHashedPassword(user, oldHash, password + "x"));

        var newHash = currentHasher.HashPassword(user, password);
        Assert.Equal(PasswordVerificationResult.Success, currentHasher.VerifyHashedPassword(user, newHash, password));
        Assert.NotEqual(oldHash, newHash);
        // Сіль: два хеші того самого пароля різні.
        Assert.NotEqual(newHash, currentHasher.HashPassword(user, password));
    }

    // БОНУС (поглиблення «втрата чинності старого сеансу після серверної події»):
    // за замовчуванням security stamp перевіряється раз на 30 хвилин, тому в тесті інтервал = 0.
    // Якщо цей тест падає, видаліть лише його: два інші поглиблення від нього не залежать.
    [Fact]
    public async Task Deepening_SecurityStampChange_InvalidatesExistingSession()
    {
        var userName = "stamp" + Guid.NewGuid().ToString("N")[..8];
        var password = NewPassword();
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.Configure<SecurityStampValidatorOptions>(options =>
                    options.ValidationInterval = TimeSpan.Zero)));
        try
        {
            using var client = NewClient(host);
            using (var register = await client.PostAsJsonAsync("/api/auth/register", new
            {
                userName, email = userName + "@example.test", displayName = "Stamp", password
            }))
                Assert.Equal(HttpStatusCode.Created, register.StatusCode);

            using (var login = await client.PostAsJsonAsync("/api/auth/login", new { userName, password }))
                Assert.Equal(HttpStatusCode.NoContent, login.StatusCode);
            using (var before = await client.GetAsync("/api/auth/session-check"))
                Assert.Equal(HttpStatusCode.NoContent, before.StatusCode);

            // Серверна подія: зміна security stamp (наприклад, скидання пароля або відкликання сеансів).
            await using (var scope = host.Services.CreateAsyncScope())
            {
                var users = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                var user = await users.FindByNameAsync(userName);
                Assert.NotNull(user);
                Assert.True((await users.UpdateSecurityStampAsync(user!)).Succeeded);
            }

            using var after = await client.GetAsync("/api/auth/session-check");
            Assert.Equal(HttpStatusCode.Unauthorized, after.StatusCode);
        }
        finally { await DeleteUserAsync(host, userName); }
    }
}
