using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

// ЛР 4 — VULNERABLE-стан (навмисно, лише для локального PoC на штучних даних).
// Нові mutation/child endpoint-и вимагають login, але шукають ресурс ЛИШЕ за id:
// немає порівняння з principal, немає перевірки ролі для triage (IDOR/BOLA + вертикальне підвищення).
public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents");

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", async (IncidentQueries queries, CancellationToken cancellationToken) =>
        {
            var summary = await queries.GetSeveritySummaryAsync(cancellationToken);
            return Results.Ok(summary);
        })
        .WithName("GetSeveritySummary")
        .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>();

        // VULNERABLE: лише login, без ресурсного рішення.
        group.MapPut("/{id:guid}", UpdateAsync).RequireAuthorization();
        group.MapDelete("/{id:guid}", DeleteAsync).RequireAuthorization();
        group.MapPost("/{id:guid}/triage", TriageAsync).RequireAuthorization();

        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .WithTags("Incidents")
            .RequireAuthorization();

        return endpoints;
    }

    private static async Task<IResult> GetListAsync(
        string? status,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        IncidentStatus? parsedStatus = null;
        if (status is not null)
        {
            if (!Enum.TryParse<IncidentStatus>(status, ignoreCase: true, out var candidate)
                || !Enum.IsDefined(candidate))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    ["status"] = ["Допустимі значення: New, Triaged, InProgress, Resolved, Closed."]
                });
            }

            parsedStatus = candidate;
        }

        return Results.Ok(await queries.GetListAsync(parsedStatus, cancellationToken));
    }

    // VULNERABLE (стан після ЛР 3): шукає інцидент лише за id, не знає про поточного користувача.
    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await queries.GetDetailsAsync(id, cancellationToken);
        return incident is null
            ? Results.Problem(
                title: "Інцидент не знайдено",
                detail: $"Інцидент '{id}' не існує.",
                statusCode: StatusCodes.Status404NotFound)
            : Results.Ok(incident);
    }

    // VULNERABLE: будь-який автентифікований користувач змінює будь-який інцидент за id;
    // до того ж Status приймається з тіла звичайного update.
    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return Results.Problem(title: "Інцидент не знайдено", statusCode: StatusCodes.Status404NotFound);
        }

        if (string.IsNullOrWhiteSpace(request.Title) || string.IsNullOrWhiteSpace(request.Description))
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["title"] = ["Назва й опис обов'язкові."]
            });
        }

        incident.Title = request.Title.Trim();
        incident.Description = request.Description.Trim();
        if (request.Status is not null
            && Enum.TryParse<IncidentStatus>(request.Status, ignoreCase: true, out var forgedStatus))
        {
            incident.Status = forgedStatus;   // VULNERABLE: protected status з body
        }

        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken);
        return Results.Ok(ToListItem(incident));
    }

    // VULNERABLE: видаляє будь-який інцидент за id.
    private static async Task<IResult> DeleteAsync(
        Guid id,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return Results.Problem(title: "Інцидент не знайдено", statusCode: StatusCodes.Status404NotFound);
        }

        db.Incidents.Remove(incident);
        await db.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    // VULNERABLE: privileged transition без перевірки ролі Analyst — Reporter теж може.
    private static async Task<IResult> TriageAsync(
        Guid id,
        TriageIncidentRequest? request,
        HttpContext httpContext,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return Results.Problem(title: "Інцидент не знайдено", statusCode: StatusCodes.Status404NotFound);
        }

        if (incident.Status != IncidentStatus.New)
        {
            return Results.Problem(
                title: "Перехід недоступний",
                detail: "Triage можливий лише зі статусу New.",
                statusCode: StatusCodes.Status409Conflict);
        }

        _ = Guid.TryParse(httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier), out var actorId);
        var note = request?.Note;
        var now = DateTimeOffset.UtcNow;
        incident.Status = IncidentStatus.Triaged;
        incident.UpdatedAtUtc = now;
        db.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(),
            IncidentId = incident.Id,
            ChangedByUserId = actorId,
            OldStatus = IncidentStatus.New,
            NewStatus = IncidentStatus.Triaged,
            Note = string.IsNullOrWhiteSpace(note) ? "Первинна оцінка." : note.Trim(),
            CreatedAtUtc = now
        });
        await db.SaveChangesAsync(cancellationToken);
        return Results.Ok(new TriageIncidentResponse(incident.Id, incident.Status.ToString()));
    }

    // VULNERABLE: child resource за прямим id — без перевірки parent incident і internal-прапорця.
    private static async Task<IResult> GetCommentAsync(
        Guid id,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        var comment = await db.IncidentComments
            .AsNoTracking()
            .Where(item => item.Id == id)
            .Select(item => new IncidentCommentDetailsResponse(
                item.Id,
                item.IncidentId,
                item.Author.DisplayName,
                item.Text,
                item.CreatedAtUtc))
            .SingleOrDefaultAsync(cancellationToken);

        return comment is null
            ? Results.Problem(title: "Коментар не знайдено", statusCode: StatusCodes.Status404NotFound)
            : Results.Ok(comment);
    }

    private static IncidentListItemResponse ToListItem(Incident incident) => new(
        incident.Id,
        incident.Title,
        incident.Severity.ToString(),
        incident.Status.ToString(),
        incident.OccurredAtUtc,
        incident.CreatedAtUtc);
}
