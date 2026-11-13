using System.Net;
using System.Net.Http.Json;
using Microsoft.Extensions.Configuration;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

// ЛР 6, REG-RL-02: rate limit GET /api/incidents/search — partition = id користувача,
// quota, узгоджений 429 (Problem Details + Retry-After), ізоляція partitions, відновлення після вікна.
public sealed class Lab06RateLimitTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string SeedPassword => Lab06TestData.SeedPassword;

    // ------------------------------------------------------------------ REG-RL-02 (search limiter)

    [Fact]
    public async Task RegRl02_Search_PerUserQuota_Returns429_OtherPartitionUnaffected_ThenRecovers()
    {
        // Окремий host із малою quota: лічильники належать host, інші тести квоту не витрачають.
        using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureAppConfiguration((_, config) =>
                config.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["RateLimit:Search:PermitLimit"] = "3",
                    ["RateLimit:Search:WindowSeconds"] = "4"
                })));
        using var alice = await host.LoginAsync("alice", SeedPassword);
        using var bob = await host.LoginAsync("bob", SeedPassword);
        const string search = "/api/incidents/search?q=USB";

        for (var attempt = 0; attempt < 3; attempt++)
        {
            using var allowed = await alice.GetAsync(search);
            Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
        }

        using var limited = await alice.GetAsync(search);
        Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
        Assert.Equal("application/problem+json", limited.Content.Headers.ContentType?.MediaType);
        Assert.NotNull(limited.Headers.RetryAfter);

        // Інший partition (Bob) має власний лічильник; маршрут без policy не обмежено.
        using var otherUser = await bob.GetAsync(search);
        Assert.Equal(HttpStatusCode.OK, otherUser.StatusCode);
        using var withoutPolicy = await alice.GetAsync("/api/incidents");
        Assert.Equal(HttpStatusCode.OK, withoutPolicy.StatusCode);

        // Rate limit не підміняє authorization: результат Alice — лише її інциденти (A-11 не змінено).
        await Task.Delay(TimeSpan.FromSeconds(4.5));   // вікно + запас
        var recovered = await alice.GetFromJsonAsync<List<IncidentListItemResponse>>(search);
        Assert.NotNull(recovered);
        Assert.All(recovered, item => Assert.NotEqual(Guid.Parse("20000000-0000-0000-0000-000000000004"), item.Id));
    }
}
