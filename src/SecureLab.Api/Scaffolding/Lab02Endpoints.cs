using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Scaffolding;

public static class Lab02Endpoints
{
    public static void MapLab02Endpoints(this WebApplication app)
    {
        // 1. ВРАЗЛИВИЙ ПОШУК (SCAFFOLD STATE) - ЗАЛИШАЄМО БЕЗ ЗМІН ДЛЯ ЕТАПУ 3
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            var sortExpression = sortBy switch 
            { 
                null or "" or "createdAtUtc" => "created_at_utc DESC", 
                _ => sortBy 
            };

            var sql = "SELECT * FROM incidents WHERE title ILIKE '%" + (q ?? "") + "%' OR description ILIKE '%" + (q ?? "") + "%' ORDER BY " + sortExpression;

            // Цей рядок виконує SQL-ін'єкцію, змішуючи дані та структуру
            var incidents = await db.Incidents.FromSqlRaw(sql).ToListAsync(ct);

            var items = incidents.Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc));

            return Results.Ok(items);
        });

        // 2. ЗАХИЩЕНИЙ POST (ЕТАП 2 - НА ОЦІНКУ "ВІДМІННО")
        app.MapPost("/api/incidents", async (CreateIncidentRequest request, SecureLabDbContext db, CancellationToken ct) =>
        {
            var now = DateTimeOffset.UtcNow;
            var errors = new Dictionary<string, string[]>();

            // 1. Базові перевірки (вимірюємо довжину ДО Trim)
            if (string.IsNullOrWhiteSpace(request.Title))
                errors["title"] = ["Назва обов'язкова."];
            else if (request.Title.Length > 160)
                errors["title"] = ["Назва не повинна перевищувати 160 символів."];

            if (string.IsNullOrWhiteSpace(request.Description))
                errors["description"] = ["Опис обов'язковий."];
            else if (request.Description.Length > 4000)
                errors["description"] = ["Опис не повинен перевищувати 4000 символів."];

            // 2. Перевірка Enum (захищає від числових значень типу "7")
            var severityIsValid = Enum.TryParse<IncidentSeverity>(request.Severity, ignoreCase: true, out var severity)
                                  && Enum.IsDefined(severity);
            if (!severityIsValid)
                errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];

            // 3. Перевірка дати (не далі ніж +5 хв)
            if (request.OccurredAtUtc is null)
                errors["occurredAtUtc"] = ["Час виникнення обов'язковий."];
            else if (request.OccurredAtUtc > now.AddMinutes(5))
                errors["occurredAtUtc"] = ["Час виникнення не може бути в майбутньому більш ніж на 5 хвилин."];

            // Нормалізація полів по одному разу
            var title = request.Title?.Trim() ?? "";
            var description = request.Description?.Trim() ?? "";

            // 4. Cross-field правило (Т-09): для High/Critical довжина опису >= 40 символів
            if (severityIsValid && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical))
            {
                if (description.Length < 40)
                    errors["description"] = ["Для рівнів High та Critical опис має містити щонайменше 40 символів."];
            }

            // 5. Додаткове предметне правило на "Відмінно" (Т-10): опис не дорівнює назві
            if (!errors.ContainsKey("description") && description.Equals(title, StringComparison.Ordinal))
            {
                errors["description"] = ["Опис не може повністю збігатися з назвою інциденту."];
            }

            // 6. Повернення 400 Bad Request ДО запиту в БД
            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            var occurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime();

            // 7. Предметний конфлікт 409 (Т-03): активний дублікат (чутливо до регістру)
            var existingIncident = await db.Incidents
                .AsNoTracking()
                .AnyAsync(item => item.Title == title && 
                                  (item.Status == IncidentStatus.New || 
                                   item.Status == IncidentStatus.Triaged || 
                                   item.Status == IncidentStatus.InProgress || 
                                   item.Status == IncidentStatus.Resolved), ct);

            if (existingIncident)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Конфлікт предметного стану",
                    detail: "Інцидент із такою назвою вже існує в активному статусі.");
            }

            // 8. Створення сутності (Захист від Overposting: сервер сам ставить id, owner, status)
            var incident = new Incident
            {
                Id = Guid.NewGuid(),
                Title = title,
                Description = description,
                Severity = severity,
                Status = IncidentStatus.New,
                OccurredAtUtc = occurredAtUtc,
                CreatedAtUtc = now,
                UpdatedAtUtc = now,
                OwnerUserId = DbSeeder.AliceId // Власник фіксований для ЛР 2
            };

            db.Incidents.Add(incident);
            await db.SaveChangesAsync(ct);

            // 9. Response DTO
            var response = new CreatedIncidentResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc);

            return Results.Created($"/api/incidents/{incident.Id}", response);
        });
    }
}

// === КОНТРАКТИ ===
public sealed record CreateIncidentRequest(
    string? Title,
    string? Description,
    string? Severity,
    DateTimeOffset? OccurredAtUtc);

public sealed record CreatedIncidentResponse(
    Guid Id,
    string Title,
    string Severity,
    string Status,
    DateTimeOffset OccurredAtUtc,
    DateTimeOffset CreatedAtUtc);