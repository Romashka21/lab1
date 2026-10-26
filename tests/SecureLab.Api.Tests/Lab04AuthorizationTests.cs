using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

// ЛР 4: один host і по ОДНОМУ клієнту на користувача для всього класу
// (кожен клієнт має власну cookie; так не вичерпуємо rate limit входу ЛР 3).
public sealed class Lab04Sessions : IAsyncLifetime
{
    public SecureLabApiFactory Factory { get; } = new();
    public HttpClient Alice { get; private set; } = null!;
    public HttpClient Bob { get; private set; } = null!;
    public HttpClient Morgan { get; private set; } = null!;
    public HttpClient Admin { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        var password = Environment.GetEnvironmentVariable("SeedUsers__Password")
            ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");
        Alice = await Factory.LoginAsync("alice", password);
        Bob = await Factory.LoginAsync("bob", password);
        Morgan = await Factory.LoginAsync("morgan", password);
        Admin = await Factory.LoginAsync("admin", password);
    }

    public async Task DisposeAsync()
    {
        Alice.Dispose();
        Bob.Dispose();
        Morgan.Dispose();
        Admin.Dispose();
        await Factory.DisposeAsync();
    }
}

// Матриця перевірок A-01…A-12 (A-08b — обраний контракт, політика 404 для чужого ресурсу).
public sealed class Lab04AuthorizationTests(Lab04Sessions s) : IClassFixture<Lab04Sessions>
{
    private static readonly Guid AliceCommentId = Guid.Parse("30000000-0000-0000-0000-000000000001");
    private static readonly Guid BobCommentId = Guid.Parse("30000000-0000-0000-0000-000000000002");
    private static readonly Guid InternalCommentId = Guid.Parse("30000000-0000-0000-0000-000000000003");
    private static readonly Guid BobSearchIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000004");
    private const string BobIncidentTitle = "Невідома спроба входу";

    private static string IncidentPath(Guid id) => $"/api/incidents/{id}";

    // Власний інцидент для mutation-тестів: новий запис завжди New, повторний запуск не залежить від seed.
    private static async Task<Guid> CreateIncidentAsync(HttpClient client, string prefix)
    {
        using var response = await client.PostAsJsonAsync("/api/incidents", new
        {
            title = $"{prefix}-{Guid.NewGuid():N}",
            description = "Синтетичний запис для перевірки авторизації ЛР 4.",
            severity = "Low",
            occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
        });
        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var created = await response.Content.ReadFromJsonAsync<CreatedIncidentResponse>();
        Assert.NotNull(created);
        return created.Id;
    }

    private async Task DeleteFromDbAsync(Guid id)
    {
        await using var scope = s.Factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(incident => incident.Id == id).ExecuteDeleteAsync();
    }

    // State assertion: стан читається напряму з БД, незалежно від API.
    private async Task<(Guid Owner, string Title, string Description, IncidentStatus Status)> StateAsync(Guid id)
    {
        await using var scope = s.Factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.AsNoTracking().SingleAsync(item => item.Id == id);
        return (incident.OwnerUserId, incident.Title, incident.Description, incident.Status);
    }

    private async Task<int> HistoryCountAsync(Guid id)
    {
        await using var scope = s.Factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.IncidentStatusHistory.CountAsync(item => item.IncidentId == id);
    }

    private static async Task<List<Guid>> CommentIdsAsync(HttpResponseMessage response)
    {
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        return document.RootElement.GetProperty("comments").EnumerateArray()
            .Select(comment => comment.GetProperty("id").GetGuid())
            .ToList();
    }

    // ------------------------------------------------------------------ A-01

    [Fact]
    public async Task A01_Anonymous_ProtectedIncidentRoutes_Return401_NotRedirect_NotHtml()
    {
        using var anonymous = s.Factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false
        });

        string[] paths =
        [
            IncidentPath(DbSeeder.AliceIncidentId),
            "/api/incidents",
            "/api/incidents/severity-summary",
            "/api/incidents/search?q=USB",
            $"/api/incident-comments/{AliceCommentId}"
        ];

        foreach (var path in paths)
        {
            using var response = await anonymous.GetAsync(path);
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
            Assert.Null(response.Headers.Location);
            Assert.NotEqual("text/html", response.Content.Headers.ContentType?.MediaType);
        }
    }

    // ------------------------------------------------------------------ A-02 / A-03 / A-03R

    [Fact]
    public async Task A02_Details_AsOwner_ReturnsOwnIncident()
    {
        using var response = await s.Alice.GetAsync(IncidentPath(DbSeeder.AliceIncidentId));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceIncidentId, document.RootElement.GetProperty("id").GetGuid());
        Assert.False(document.RootElement.TryGetProperty("ownerUserId", out _));
    }

    [Fact]
    public async Task A03_Details_AsOtherReporter_ReturnsNotFound_WithoutBobData()
    {
        using var response = await s.Alice.GetAsync(IncidentPath(DbSeeder.BobIncidentId));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(BobIncidentTitle, body, StringComparison.Ordinal);
        Assert.DoesNotContain(DbSeeder.BobIncidentId.ToString(), body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task A03R_Details_AsAnalyst_ReturnsAliceIncident()
    {
        using var response = await s.Morgan.GetAsync(IncidentPath(DbSeeder.AliceIncidentId));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        using var document = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        Assert.Equal(DbSeeder.AliceIncidentId, document.RootElement.GetProperty("id").GetGuid());
    }

    // ------------------------------------------------------------------ A-04 (mutation perimeter)

    [Fact]
    public async Task A04_UpdateAndDelete_AsNonOwner_ReturnNotFound_AndDoNotChangeBobIncident()
    {
        var before = await StateAsync(DbSeeder.BobIncidentId);

        using var update = await s.Alice.PutAsJsonAsync(IncidentPath(DbSeeder.BobIncidentId), new
        {
            title = "Змінено Alice",
            description = "Спроба змінити чужий інцидент без права на це."
        });
        using var delete = await s.Alice.DeleteAsync(IncidentPath(DbSeeder.BobIncidentId));

        Assert.Equal(HttpStatusCode.NotFound, update.StatusCode);
        Assert.Equal(HttpStatusCode.NotFound, delete.StatusCode);
        Assert.Equal(before, await StateAsync(DbSeeder.BobIncidentId));
    }

    [Fact]
    public async Task A04_UpdateAndDelete_AsAnalyst_ReturnForbidden_AndDoNotChangeAliceIncident()
    {
        // Analyst бачить інцидент (A-03R), але право читання не дає права змінювати чи видаляти.
        var before = await StateAsync(DbSeeder.AliceIncidentId);

        using var update = await s.Morgan.PutAsJsonAsync(IncidentPath(DbSeeder.AliceIncidentId), new
        {
            title = "Змінено Morgan",
            description = "Analyst не має права на content update інциденту."
        });
        using var delete = await s.Morgan.DeleteAsync(IncidentPath(DbSeeder.AliceIncidentId));

        Assert.Equal(HttpStatusCode.Forbidden, update.StatusCode);
        Assert.Equal(HttpStatusCode.Forbidden, delete.StatusCode);
        Assert.Equal(before, await StateAsync(DbSeeder.AliceIncidentId));
    }

    [Fact]
    public async Task Update_AsOwner_ChangesOnlyContent()
    {
        var id = await CreateIncidentAsync(s.Alice, "UPD");
        try
        {
            var newTitle = $"UPD-ok-{Guid.NewGuid():N}";
            using var response = await s.Alice.PutAsJsonAsync(IncidentPath(id), new
            {
                title = newTitle,
                description = "Дозволена зміна лише content-полів власником."
            });

            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            var after = await StateAsync(id);
            Assert.Equal(newTitle, after.Title);
            Assert.Equal(DbSeeder.AliceId, after.Owner);
            Assert.Equal(IncidentStatus.New, after.Status);
        }
        finally
        {
            await DeleteFromDbAsync(id);
        }
    }

    [Fact]
    public async Task Delete_AsOwner_NewIncident_Returns204_ThenNotFound()
    {
        var id = await CreateIncidentAsync(s.Alice, "DEL");
        try
        {
            using var otherReporter = await s.Bob.DeleteAsync(IncidentPath(id));
            Assert.Equal(HttpStatusCode.NotFound, otherReporter.StatusCode);
            Assert.Equal(DbSeeder.AliceId, (await StateAsync(id)).Owner);

            using var owner = await s.Alice.DeleteAsync(IncidentPath(id));
            Assert.Equal(HttpStatusCode.NoContent, owner.StatusCode);

            using var read = await s.Alice.GetAsync(IncidentPath(id));
            Assert.Equal(HttpStatusCode.NotFound, read.StatusCode);
        }
        finally
        {
            await DeleteFromDbAsync(id);
        }
    }

    // ------------------------------------------------------------------ A-05

    [Fact]
    public async Task A05_List_AsReporter_ContainsOnlyOwnIncidents()
    {
        var aliceList = await s.Alice.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");
        Assert.NotNull(aliceList);
        Assert.Contains(aliceList, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.DoesNotContain(aliceList, item => item.Id == DbSeeder.BobIncidentId);
        Assert.DoesNotContain(aliceList, item => item.Id == BobSearchIncidentId);

        // Кожен рядок відповіді справді належить Alice.
        var ids = aliceList.Select(item => item.Id).ToList();
        await using var scope = s.Factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var foreignRows = await db.Incidents.CountAsync(
            incident => ids.Contains(incident.Id) && incident.OwnerUserId != DbSeeder.AliceId);
        Assert.Equal(0, foreignRows);

        // Analyst за матрицею бачить інциденти різних власників.
        var morganList = await s.Morgan.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents");
        Assert.NotNull(morganList);
        Assert.Contains(morganList, item => item.Id == DbSeeder.AliceIncidentId);
        Assert.Contains(morganList, item => item.Id == DbSeeder.BobIncidentId);
    }

    // ------------------------------------------------------------------ A-06 / A-07 (privileged transition)

    [Fact]
    public async Task A06_Triage_AsReporterOwner_IsForbidden_AndStatusUnchanged()
    {
        var id = await CreateIncidentAsync(s.Alice, "A06");
        try
        {
            using var response = await s.Alice.PostAsJsonAsync($"{IncidentPath(id)}/triage",
                new { note = "Reporter намагається виконати privileged transition." });

            Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
            Assert.Contains("traceId", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
            Assert.Equal(IncidentStatus.New, (await StateAsync(id)).Status);
            Assert.Equal(0, await HistoryCountAsync(id));
        }
        finally
        {
            await DeleteFromDbAsync(id);
        }
    }

    [Fact]
    public async Task A07_Triage_AsAnalyst_NewToTriaged_ThenConflict_AdminHasNoImplicitRight()
    {
        var id = await CreateIncidentAsync(s.Alice, "A07");
        try
        {
            using var admin = await s.Admin.PostAsJsonAsync($"{IncidentPath(id)}/triage", new { note = "admin" });
            Assert.Equal(HttpStatusCode.NotFound, admin.StatusCode);
            Assert.Equal(IncidentStatus.New, (await StateAsync(id)).Status);

            using var first = await s.Morgan.PostAsJsonAsync($"{IncidentPath(id)}/triage",
                new { note = "Первинну оцінку виконано." });
            Assert.Equal(HttpStatusCode.OK, first.StatusCode);
            using (var document = JsonDocument.Parse(await first.Content.ReadAsStringAsync()))
            {
                Assert.Equal("Triaged", document.RootElement.GetProperty("status").GetString());
            }

            Assert.Equal(IncidentStatus.Triaged, (await StateAsync(id)).Status);
            Assert.Equal(1, await HistoryCountAsync(id));

            using var second = await s.Morgan.PostAsJsonAsync($"{IncidentPath(id)}/triage", new { note = "ще раз" });
            Assert.Equal(HttpStatusCode.Conflict, second.StatusCode);
            Assert.Equal(1, await HistoryCountAsync(id));
        }
        finally
        {
            await DeleteFromDbAsync(id);
        }
    }

    // ------------------------------------------------------------------ A-08b (contract rejects forged fields)

    [Fact]
    public async Task A08b_Update_WithForgedOwnerRoleStatus_Returns400_AndProtectedStateUnchanged()
    {
        var id = await CreateIncidentAsync(s.Alice, "A08");
        try
        {
            var before = await StateAsync(id);

            using var forged = await s.Alice.PutAsJsonAsync(IncidentPath(id), new
            {
                title = "A08-forged",
                description = "Спроба підмінити серверні поля через звичайний update.",
                ownerUserId = DbSeeder.BobId,
                status = "Closed",
                role = "Analyst"
            });
            Assert.Equal(HttpStatusCode.BadRequest, forged.StatusCode);
            Assert.Equal("application/problem+json", forged.Content.Headers.ContentType?.MediaType);
            Assert.Equal(before, await StateAsync(id));

            using var forgedTriage = await s.Alice.PostAsJsonAsync($"{IncidentPath(id)}/triage",
                new { note = "x", status = "Triaged", isTransitionAllowed = true });
            Assert.Equal(HttpStatusCode.BadRequest, forgedTriage.StatusCode);
            Assert.Equal(before, await StateAsync(id));
        }
        finally
        {
            await DeleteFromDbAsync(id);
        }
    }

    // ------------------------------------------------------------------ A-10 (policy 404)

    [Fact]
    public async Task A10_ForeignAndUnknownIncident_AreIndistinguishable()
    {
        using var foreign = await s.Alice.GetAsync(IncidentPath(DbSeeder.BobIncidentId));
        using var unknown = await s.Alice.GetAsync(IncidentPath(Guid.NewGuid()));

        Assert.Equal(HttpStatusCode.NotFound, foreign.StatusCode);
        Assert.Equal(unknown.StatusCode, foreign.StatusCode);
        Assert.Equal(
            unknown.Content.Headers.ContentType?.ToString(),
            foreign.Content.Headers.ContentType?.ToString());

        var foreignBody = await foreign.Content.ReadFromJsonAsync<JsonObject>();
        var unknownBody = await unknown.Content.ReadFromJsonAsync<JsonObject>();
        Assert.NotNull(foreignBody);
        Assert.NotNull(unknownBody);
        foreignBody.Remove("traceId");
        unknownBody.Remove("traceId");
        Assert.True(JsonNode.DeepEquals(unknownBody, foreignBody));
    }

    // ------------------------------------------------------------------ A-11 (search і severity-summary)

    [Fact]
    public async Task A11_SearchAndSeveritySummary_AsReporter_DoNotRevealForeignIncidents()
    {
        var aliceSearch = await s.Alice.GetFromJsonAsync<List<IncidentListItemResponse>>(
            "/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien"));
        Assert.NotNull(aliceSearch);
        Assert.Empty(aliceSearch);

        var morganSearch = await s.Morgan.GetFromJsonAsync<List<IncidentListItemResponse>>(
            "/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien"));
        Assert.NotNull(morganSearch);
        Assert.Contains(morganSearch, item => item.Id == BobSearchIncidentId);

        // У seed єдиний High-інцидент належить Bob: у зведенні Alice його бути не може.
        var aliceSummary = await s.Alice.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary");
        Assert.NotNull(aliceSummary);
        Assert.DoesNotContain(aliceSummary, item => item.Severity == "High");
        Assert.Contains(aliceSummary, item => item.Severity == "Medium");

        var morganSummary = await s.Morgan.GetFromJsonAsync<List<IncidentSeveritySummaryResponse>>(
            "/api/incidents/severity-summary");
        Assert.NotNull(morganSummary);
        Assert.Contains(morganSummary, item => item.Severity == "High");
    }

    // ------------------------------------------------------------------ A-12 (child resource, internal comment)

    [Fact]
    public async Task A12_CommentsAndInternalComment_FollowParentAndRole()
    {
        using var foreignComment = await s.Alice.GetAsync($"/api/incident-comments/{BobCommentId}");
        Assert.Equal(HttpStatusCode.NotFound, foreignComment.StatusCode);
        Assert.DoesNotContain("журналу автентифікації", await foreignComment.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        using var internalForOwner = await s.Alice.GetAsync($"/api/incident-comments/{InternalCommentId}");
        Assert.Equal(HttpStatusCode.NotFound, internalForOwner.StatusCode);

        using var ownPublic = await s.Alice.GetAsync($"/api/incident-comments/{AliceCommentId}");
        Assert.Equal(HttpStatusCode.OK, ownPublic.StatusCode);

        using var aliceDetails = await s.Alice.GetAsync(IncidentPath(DbSeeder.AliceIncidentId));
        Assert.DoesNotContain(InternalCommentId, await CommentIdsAsync(aliceDetails));

        using var internalForAnalyst = await s.Morgan.GetAsync($"/api/incident-comments/{InternalCommentId}");
        Assert.Equal(HttpStatusCode.OK, internalForAnalyst.StatusCode);

        using var morganDetails = await s.Morgan.GetAsync(IncidentPath(DbSeeder.AliceIncidentId));
        Assert.Contains(InternalCommentId, await CommentIdsAsync(morganDetails));
    }
}
