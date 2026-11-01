using System.Net;
using System.Net.Http.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Tests;

public sealed class Lab04SearchTotalTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string Pw => Environment.GetEnvironmentVariable("SeedUsers__Password")!;

    private async Task<string> SeedAsync(int alice, int bob)
    {
        var q = "BOUND-" + Guid.NewGuid().ToString("N")[..8];
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        for (var i = 0; i<alice + bob; i++)
        {
            var isAlice = i < alice;
            db.Incidents.Add(new Incident
            {
                Id = Guid.NewGuid(),
                OwnerUserId = isAlice ? DbSeeder.AliceId : DbSeeder.BobId,
                Title = $"{q} {(isAlice ? "alice" : "bob")} {i}",
                Description = "BOUND-WEB04",
                OccurredAtUtc = DateTimeOffset.UtcNow,
                CreatedAtUtc = DateTimeOffset.UtcNow,
                UpdatedAtUtc = DateTimeOffset.UtcNow
            });
        }
        await db.SaveChangesAsync();
        return q;
    }

    private async Task<int> DbCountAsync(Guid owner, string q)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.Incidents.CountAsync(i => i.OwnerUserId == owner && EF.Functions.Like(i.Title, q + "%"));

    }
    private async Task CleanupAsync(string q)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(i => EF.Functions.Like(i.Title, q + "%")).ExecuteDeleteAsync();
    }
    private async Task<(List<IncidentListItemResponse> Items, string? Total)> SearchAsync(string user, string q)
    {
        using var client = await factory.LoginAsync(user, Pw);
        using var response = await client.GetAsync($"/api/incidents/search?q={q}");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        var items = await response.Content.ReadFromJsonAsync<List<IncidentListItemResponse>>();
        response.Headers.TryGetValues("X-Total-Count", out var total);
        return (items!, total?.Single());
    }

    [Theory]
    [InlineData(49,49)]
    [InlineData(50,50)]
    [InlineData(51,50)]

    public async Task Alice_PageMax50_TotalIsAccessibleMatches(int aliceMatches, int page)
    {
        var q = await SeedAsync(aliceMatches, 7);
        try
        {
            var (items, total) = await SearchAsync("alice", q);
            Assert.Equal(page, items.Count);
            Assert.All(items, x => Assert.Contains(" alice ", x.Title));
            Assert.Equal($"{aliceMatches}", total);
            Assert.Equal($"{await DbCountAsync(DbSeeder.AliceId, q)}", total);

        }
        finally
        {
            await CleanupAsync(q);
        }
    }

    [Fact]
    public async Task Bob_PositiveControl_SevenOwnMatches ()
    {
        var q = await SeedAsync(51, 7);
        try
        {
            var (items, total) = await SearchAsync("bob", q);
            Assert.Equal(7, items.Count);
            Assert.All(items, x=> Assert.Contains(" bob ", x.Title));
            Assert.Equal("7", total);
            Assert.Equal($"{await DbCountAsync(DbSeeder.BobId, q)}", total);
        }
        finally
        {
            await CleanupAsync(q);
        }
    }

}