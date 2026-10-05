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
        // 1. БЕЗПЕЧНИЙ ПОШУК (ЕТАП 4): значення q іде параметром, структуру запиту обирає allowlist
        app.MapGet("/api/incidents/search", async (string? q, string? sortBy, SecureLabDbContext db, CancellationToken ct) =>
        {
            // allowlist: порожнє або відсутнє значення означає createdAtUtc, усе інше поза переліком -> 400
            var sortKey = string.IsNullOrEmpty(sortBy) ? "createdAtUtc" : sortBy;
            if (sortKey is not ("createdAtUtc" or "severity" or "status"))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["sortBy"] = ["Допустимі значення: createdAtUtc, severity, status."]
                });
            }

            // значення пошуку: екрануємо %, _, \ і передаємо ОКРЕМО від тексту SQL (параметр @pattern)
            var pattern = "%" + EscapeLike(q ?? "") + "%";

            var found = db.Incidents
                .AsNoTracking()
                .Where(incident => EF.Functions.ILike(incident.Title, pattern, "\\")
                                   || EF.Functions.ILike(incident.Description, pattern, "\\"));

            IQueryable<Incident> ordered = sortKey switch
            {
                "severity" => found
                    .OrderBy(incident => incident.Severity == IncidentSeverity.Critical ? 0 :
                                         incident.Severity == IncidentSeverity.High ? 1 :
                                         incident.Severity == IncidentSeverity.Medium ? 2 : 3)
                    .ThenBy(incident => incident.Id),
                "status" => found
                    .OrderBy(incident => incident.Status == IncidentStatus.New ? 0 :
                                         incident.Status == IncidentStatus.Triaged ? 1 :
                                         incident.Status == IncidentStatus.InProgress ? 2 :
                                         incident.Status == IncidentStatus.Resolved ? 3 : 4)
                    .ThenBy(incident => incident.Id),
                _ => found
                    .OrderByDescending(incident => incident.CreatedAtUtc)
                    .ThenBy(incident => incident.Id)
            };

            var items = await ordered
                .Take(50)
                .Select(incident => new IncidentListItemResponse(
                    incident.Id,
                    incident.Title,
                    incident.Severity.ToString(),
                    incident.Status.ToString(),
                    incident.OccurredAtUtc,
                    incident.CreatedAtUtc))
                .ToListAsync(ct);

            return Results.Ok(items);
        });

        // 2. ЗАХИЩЕНИЙ POST (ЕТАП 2)
        app.MapPost("/api/incidents", async (CreateIncidentRequest request, SecureLabDbContext db, CancellationToken ct) =>
        {
            var now = DateTimeOffset.UtcNow;
            var errors = new Dictionary<string, string[]>();

            // 1. Базові перевірки (довжину міряємо на надісланому значенні, до Trim)
            if (string.IsNullOrWhiteSpace(request.Title))
                errors["title"] = ["Назва обов'язкова."];
            else if (request.Title.Length > 160)
                errors["title"] = ["Назва не повинна перевищувати 160 символів."];

            if (string.IsNullOrWhiteSpace(request.Description))
                errors["description"] = ["Опис обов'язковий."];
            else if (request.Description.Length > 4000)
                errors["description"] = ["Опис не повинен перевищувати 4000 символів."];

            // 2. Enum: TryParse + IsDefined (відхиляє "7"); кому відсікаємо окремо ("Medium, High")
            IncidentSeverity severity = default;
            var severityIsValid = request.Severity is not null
                                  && !request.Severity.Contains(',')
                                  && Enum.TryParse(request.Severity, ignoreCase: true, out severity)
                                  && Enum.IsDefined(severity);
            if (!severityIsValid)
                errors["severity"] = ["Допустимі значення: Low, Medium, High, Critical."];

            // 3. Дата (не далі ніж +5 хв від серверного UTC now)
            if (request.OccurredAtUtc is null)
                errors["occurredAtUtc"] = ["Час виникнення обов'язковий."];
            else if (request.OccurredAtUtc > now.AddMinutes(5))
                errors["occurredAtUtc"] = ["Час виникнення не може бути в майбутньому більш ніж на 5 хвилин."];

            // Нормалізація один раз
            var title = request.Title?.Trim() ?? "";
            var description = request.Description?.Trim() ?? "";

            // 4. Cross-field (T-09): High/Critical -> опис після Trim не коротший за 40
            if (severityIsValid
                && (severity == IncidentSeverity.High || severity == IncidentSeverity.Critical)
                && !errors.ContainsKey("description")
                && description.Length < 40)
            {
                errors["description"] = ["Для рівнів High та Critical опис має містити щонайменше 40 символів."];
            }

            // 5. Додаткове правило (T-10): опис не може збігатися з назвою
            if (!errors.ContainsKey("description") && description.Equals(title, StringComparison.Ordinal))
                errors["description"] = ["Опис не може повністю збігатися з назвою інциденту."];

            // 6. 400 до звернення до БД
            if (errors.Count > 0)
                return Results.ValidationProblem(errors);

            var occurredAtUtc = request.OccurredAtUtc!.Value.ToUniversalTime();

            // 7. Конфлікт (T-03): активний дублікат за title (з урахуванням регістру); Closed не блокує
            var hasActiveDuplicate = await db.Incidents
                .AsNoTracking()
                .AnyAsync(item => item.Title == title &&
                                  (item.Status == IncidentStatus.New ||
                                   item.Status == IncidentStatus.Triaged ||
                                   item.Status == IncidentStatus.InProgress ||
                                   item.Status == IncidentStatus.Resolved), ct);

            if (hasActiveDuplicate)
            {
                return Results.Problem(
                    statusCode: StatusCodes.Status409Conflict,
                    title: "Конфлікт предметного стану",
                    detail: "Інцидент із такою назвою вже існує в активному статусі.");
            }

            // 8. Entity: server-managed поля ставить сервер (захист від overposting)
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
                OwnerUserId = DbSeeder.AliceId
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

    // Екранування метасимволів LIKE: \ -> \\, % -> \%, _ -> \_
    private static string EscapeLike(string value) =>
        value.Replace("\\", "\\\\").Replace("%", "\\%").Replace("_", "\\_");
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
