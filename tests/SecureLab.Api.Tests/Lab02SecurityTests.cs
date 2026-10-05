using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

public sealed class Lab02SecurityTests(SecureLabApiFactory factory)
    : IClassFixture<SecureLabApiFactory>
{
    private readonly HttpClient _client = factory.CreateClient();

    private static readonly Guid UsbIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000005");

    // ---------- допоміжні методи ----------

    private static object ValidBody(string title, string severity = "Low", string? description = null) => new
    {
        title,
        description = description ?? "Штучний запис для автоматичного тесту.",
        severity,
        occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10)
    };

    private async Task DeleteByTitleAsync(string title)
    {
        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
    }

    private static async Task AssertProblemAsync(HttpResponseMessage response, HttpStatusCode expected, string? errorKey = null)
    {
        Assert.Equal(expected, response.StatusCode);
        Assert.Equal("application/problem+json", response.Content.Headers.ContentType?.MediaType);

        var json = await response.Content.ReadAsStringAsync();
        using var document = JsonDocument.Parse(json);
        Assert.True(document.RootElement.TryGetProperty("title", out _));
        Assert.True(document.RootElement.TryGetProperty("status", out _));

        if (errorKey is not null)
        {
            var errors = document.RootElement.GetProperty("errors");
            Assert.True(errors.TryGetProperty(errorKey, out _), $"errors.{errorKey} відсутній: {json}");
        }

        // без внутрішніх деталей
        Assert.DoesNotContain("Exception", json, StringComparison.Ordinal);
        Assert.DoesNotContain("SELECT", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("Host=", json, StringComparison.OrdinalIgnoreCase);
    }

    // ---------- T-01 ----------

    [Fact]
    public async Task T01_ValidRequest_Returns201WithoutInternalFields()
    {
        var title = $"T01-{Guid.NewGuid():N}";
        try
        {
            using var response = await _client.PostAsJsonAsync("/api/incidents", ValidBody(title));

            Assert.Equal(HttpStatusCode.Created, response.StatusCode);
            Assert.NotNull(response.Headers.Location);

            var json = await response.Content.ReadAsStringAsync();
            using var document = JsonDocument.Parse(json);
            Assert.Equal(title, document.RootElement.GetProperty("title").GetString());
            Assert.Equal("New", document.RootElement.GetProperty("status").GetString());
            Assert.False(document.RootElement.TryGetProperty("ownerUserId", out _));
            Assert.False(document.RootElement.TryGetProperty("description", out _));
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // ---------- T-02 (Добре) ----------

    [Theory]
    [InlineData("7")]
    [InlineData("Urgent")]
    [InlineData("Medium, High")]
    public async Task T02_InvalidSeverity_Returns400WithSeverityKey(string severity)
    {
        var title = $"T02-{Guid.NewGuid():N}";
        try
        {
            using var response = await _client.PostAsJsonAsync("/api/incidents", ValidBody(title, severity));
            await AssertProblemAsync(response, HttpStatusCode.BadRequest, "severity");
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    [Fact]
    public async Task T02_EmptyTitle_Returns400WithTitleKey()
    {
        using var response = await _client.PostAsJsonAsync("/api/incidents", ValidBody("   "));
        await AssertProblemAsync(response, HttpStatusCode.BadRequest, "title");
    }

    [Fact]
    public async Task T02_DateTooFarInFuture_Returns400WithDateKey()
    {
        var title = $"T02-{Guid.NewGuid():N}";
        try
        {
            var body = new
            {
                title,
                description = "Дата з далекого майбутнього.",
                severity = "Low",
                occurredAtUtc = "2099-01-01T00:00:00Z"
            };
            using var response = await _client.PostAsJsonAsync("/api/incidents", body);
            await AssertProblemAsync(response, HttpStatusCode.BadRequest, "occurredAtUtc");
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    // ---------- T-03 (Добре) ----------

    [Fact]
    public async Task T03_DuplicateActiveTitle_Returns409()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        try
        {
            using var first = await _client.PostAsJsonAsync("/api/incidents", ValidBody(title));
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            // той самий title з пробілами по краях: після Trim це дублікат
            using var second = await _client.PostAsJsonAsync("/api/incidents", ValidBody($"  {title}  "));
            await AssertProblemAsync(second, HttpStatusCode.Conflict);
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }

    [Fact]
    public async Task T03_SameTitleDifferentCase_IsNotConflict()
    {
        var title = $"Regression-{Guid.NewGuid():N}";
        var lowerTitle = title.ToLowerInvariant();
        try
        {
            using var first = await _client.PostAsJsonAsync("/api/incidents", ValidBody(title));
            Assert.Equal(HttpStatusCode.Created, first.StatusCode);

            using var second = await _client.PostAsJsonAsync("/api/incidents", ValidBody(lowerTitle));
            Assert.Equal(HttpStatusCode.Created, second.StatusCode);
        }
        finally
        {
            await DeleteByTitleAsync(title);
            await DeleteByTitleAsync(lowerTitle);
        }
    }

    // ---------- T-09 (Добре) ----------

    [Fact]
    public async Task T09_HighSeverity_Description39Fails_Description40Passes()
    {
        var shortTitle = $"T09-{Guid.NewGuid():N}";
        var okTitle = $"T09-{Guid.NewGuid():N}";
        try
        {
            using var bad = await _client.PostAsJsonAsync("/api/incidents",
                ValidBody(shortTitle, "High", new string('x', 39)));
            await AssertProblemAsync(bad, HttpStatusCode.BadRequest, "description");

            using var good = await _client.PostAsJsonAsync("/api/incidents",
                ValidBody(okTitle, "High", new string('x', 40)));
            Assert.Equal(HttpStatusCode.Created, good.StatusCode);
        }
        finally
        {
            await DeleteByTitleAsync(shortTitle);
            await DeleteByTitleAsync(okTitle);
        }
    }

    // ---------- T-10 (Відмінно) ----------

    [Fact]
    public async Task T10_DescriptionEqualToTitle_Returns400_DifferentDescriptionPasses()
    {
        var sameTitle = $"T10-{Guid.NewGuid():N}";
        var okTitle = $"T10-{Guid.NewGuid():N}";
        try
        {
            using var bad = await _client.PostAsJsonAsync("/api/incidents",
                ValidBody(sameTitle, "Low", sameTitle));
            await AssertProblemAsync(bad, HttpStatusCode.BadRequest, "description");

            using var good = await _client.PostAsJsonAsync("/api/incidents", ValidBody(okTitle));
            Assert.Equal(HttpStatusCode.Created, good.StatusCode);
        }
        finally
        {
            await DeleteByTitleAsync(sameTitle);
            await DeleteByTitleAsync(okTitle);
        }
    }

    // ---------- S-02 (Відмінно): множина результатів ----------

    [Fact]
    public async Task S02_ControlInput_ReturnsEmptyList_AndPositiveControlReturnsOnlyUsbIncident()
    {
        const string control = "zz-no-match' OR TRUE -- ";

        using var response = await _client.GetAsync("/api/incidents/search?q=" + Uri.EscapeDataString(control));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var items = await response.Content.ReadFromJsonAsync<List<IncidentListItemResponse>>();
        Assert.NotNull(items);
        Assert.Empty(items);

        // позитивний контроль: пошук не став "надто суворим"
        var usb = await _client.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents/search?q=USB");
        Assert.NotNull(usb);
        var single = Assert.Single(usb);
        Assert.Equal(UsbIncidentId, single.Id);
    }

    [Fact]
    public async Task S02_LiteralWildcards_AreNotInterpreted()
    {
        foreach (var value in new[] { "%", "_", "\\" })
        {
            var items = await _client.GetFromJsonAsync<List<IncidentListItemResponse>>(
                "/api/incidents/search?q=" + Uri.EscapeDataString(value));
            Assert.NotNull(items);
            Assert.Empty(items);
        }
    }

    // ---------- T-04: позитивна регресія ----------

    [Fact]
    public async Task T04_ApostropheSearch_Returns200AndOBrienIncident()
    {
        using var response = await _client.GetAsync("/api/incidents/search?q=" + Uri.EscapeDataString("O'Brien"));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var items = await response.Content.ReadFromJsonAsync<List<IncidentListItemResponse>>();
        Assert.NotNull(items);
        Assert.Contains(items, item => item.Title.Contains("O'Brien", StringComparison.Ordinal));
    }

    // ---------- T-05: allowlist sortBy ----------

    [Fact]
    public async Task T05_UnknownSortBy_Returns400WithSortByKey()
    {
        using var response = await _client.GetAsync("/api/incidents/search?sortBy=price");
        await AssertProblemAsync(response, HttpStatusCode.BadRequest, "sortBy");
    }

    [Fact]
    public async Task SortBy_Severity_OrdersByRankNotAlphabet()
    {
        var items = await _client.GetFromJsonAsync<List<IncidentListItemResponse>>("/api/incidents/search?sortBy=severity");
        Assert.NotNull(items);
        var ranks = items.Select(item => item.Severity switch
        {
            "Critical" => 0, "High" => 1, "Medium" => 2, _ => 3
        }).ToList();
        Assert.Equal(ranks.OrderBy(rank => rank).ToList(), ranks);
    }

    // ---------- A-02 (Відмінно): overposting ----------

    [Fact]
    public async Task A02_Overposting_ServerManagedFieldsAreIgnored()
    {
        var title = $"A02-{Guid.NewGuid():N}";
        var sentId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var sentOwner = Guid.Parse("99999999-9999-9999-9999-999999999999");
        try
        {
            var body = new
            {
                title,
                description = "Перевірка ігнорування серверних полів.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-10),
                id = sentId,
                ownerUserId = sentOwner,
                status = "Closed",
                createdAtUtc = "2000-01-01T00:00:00Z"
            };

            using var response = await _client.PostAsJsonAsync("/api/incidents", body);
            Assert.Equal(HttpStatusCode.Created, response.StatusCode);

            var created = await response.Content.ReadFromJsonAsync<CreatedIncidentResponse>();
            Assert.NotNull(created);
            Assert.NotEqual(sentId, created.Id);
            Assert.Equal("New", created.Status);

            await using var scope = factory.Services.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
            var saved = await db.Incidents.AsNoTracking().SingleAsync(item => item.Title == title);
            Assert.Equal(DbSeeder.AliceId, saved.OwnerUserId);
            Assert.Equal(IncidentStatus.New, saved.Status);
            Assert.True(saved.CreatedAtUtc > DateTimeOffset.UtcNow.AddMinutes(-5));
        }
        finally
        {
            await DeleteByTitleAsync(title);
        }
    }
}
