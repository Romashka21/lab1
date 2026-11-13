using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Tests;

// ЛР 6: спільні передумови й читання стану для регресій hardening (стан — напряму з БД, незалежно від API).
public static class Lab06TestData
{
    public static string SeedPassword =>
        Environment.GetEnvironmentVariable("SeedUsers__Password")
        ?? throw new InvalidOperationException("Set local SeedUsers__Password outside Git.");

    public static object UpdateBody(string title, string description) => new { title, description };

    public sealed record IncidentState(string Title, string Description, IncidentStatus Status, int HistoryCount);

    public static string IncidentPath(Guid id) => $"/api/incidents/{id}";

    // Початковий ресурс створюється напряму в БД: передумова тесту не залежить від mutation API.
    public static async Task<Guid> InsertIncidentAsync(WebApplicationFactory<Program> host, Guid ownerUserId, string prefix)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var now = DateTimeOffset.UtcNow;
        var incident = new Incident
        {
            Id = Guid.NewGuid(),
            OwnerUserId = ownerUserId,
            Title = $"{prefix}-{Guid.NewGuid():N}",
            Description = "Синтетичний запис ЛР 6 для перевірки antiforgery.",
            Severity = IncidentSeverity.Low,
            Status = IncidentStatus.New,
            OccurredAtUtc = now.AddMinutes(-5),
            CreatedAtUtc = now,
            UpdatedAtUtc = now
        };
        db.Incidents.Add(incident);
        await db.SaveChangesAsync();
        return incident.Id;
    }

    // Стан читається напряму з БД, незалежно від API.
    public static async Task<IncidentState?> StateAsync(WebApplicationFactory<Program> host, Guid id)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var incident = await db.Incidents.AsNoTracking().SingleOrDefaultAsync(item => item.Id == id);
        if (incident is null)
        {
            return null;
        }

        var history = await db.IncidentStatusHistory.CountAsync(item => item.IncidentId == id);
        return new IncidentState(incident.Title, incident.Description, incident.Status, history);
    }

    public static async Task<bool> ExistsByTitleAsync(WebApplicationFactory<Program> host, string title)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        return await db.Incidents.AnyAsync(item => item.Title == title);
    }

    public static async Task DeleteIncidentsAsync(WebApplicationFactory<Program> host, params Guid[] ids)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => ids.Contains(item.Id)).ExecuteDeleteAsync();
    }

    public static async Task DeleteByTitleAsync(WebApplicationFactory<Program> host, string title)
    {
        await using var scope = host.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        await db.Incidents.Where(item => item.Title == title).ExecuteDeleteAsync();
    }
}
