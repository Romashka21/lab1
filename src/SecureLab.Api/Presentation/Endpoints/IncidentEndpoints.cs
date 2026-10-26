using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Presentation.Endpoints;

// ЛР 4: усі маршрути Incident вимагають автентифікації (група), а рішення для конкретного
// ресурсу ухвалює IncidentAuthorizationHandler. Політика: ресурс, який principal не має права
// бачити, відповідає ТАК САМО, як неіснуючий (404); видимий ресурс без права на дію — 403.
public static class IncidentEndpoints
{
    public static IEndpointRouteBuilder MapIncidentEndpoints(this IEndpointRouteBuilder endpoints)
    {
        var group = endpoints.MapGroup("/api/incidents")
            .WithTags("Incidents")
            .RequireAuthorization();

        group.MapGet("/", GetListAsync)
            .WithName("GetIncidents")
            .Produces<IReadOnlyList<IncidentListItemResponse>>()
            .ProducesValidationProblem();

        group.MapGet("/{id:guid}", GetDetailsAsync)
            .WithName("GetIncidentDetails")
            .Produces<IncidentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapGet("/severity-summary", GetSeveritySummaryAsync)
            .WithName("GetSeveritySummary")
            .Produces<IReadOnlyList<IncidentSeveritySummaryResponse>>();

        group.MapPut("/{id:guid}", UpdateAsync)
            .WithName("UpdateIncident")
            .Produces<IncidentListItemResponse>()
            .ProducesValidationProblem()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict);

        group.MapDelete("/{id:guid}", DeleteAsync)
            .WithName("DeleteIncident")
            .Produces(StatusCodes.Status204NoContent)
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound);

        group.MapPost("/{id:guid}/triage", TriageAsync)
            .WithName("TriageIncident")
            .Produces<TriageIncidentResponse>()
            .ProducesProblem(StatusCodes.Status403Forbidden)
            .ProducesProblem(StatusCodes.Status404NotFound)
            .ProducesProblem(StatusCodes.Status409Conflict);

        // Child resource поза групою — захищається окремо.
        endpoints.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .WithTags("Incidents")
            .WithName("GetIncidentComment")
            .Produces<IncidentCommentDetailsResponse>()
            .ProducesProblem(StatusCodes.Status404NotFound)
            .RequireAuthorization();

        return endpoints;
    }

    // Один helper для «чужого» і «неіснуючого»: однакові status, Content-Type і тіло (крім traceId).
    private static IResult IncidentNotFound() => Results.Problem(
        title: "Інцидент не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static IResult CommentNotFound() => Results.Problem(
        title: "Коментар не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    private static async Task<IResult> GetListAsync(
        string? status,
        HttpContext httpContext,
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

        var viewer = IncidentViewer.FromPrincipal(httpContext.User);
        if (viewer is null)
        {
            return Results.Challenge();
        }

        return Results.Ok(await queries.GetListAsync(parsedStatus, viewer, cancellationToken));
    }

    private static async Task<IResult> GetDetailsAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var incident = await queries.FindForDecisionAsync(id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentNotFound();   // політика 404: чужий = неіснуючий
        }

        var canReadInternal = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.ReadInternalComments);

        var details = await queries.GetDetailsAsync(id, canReadInternal.Succeeded, cancellationToken);
        return details is null ? IncidentNotFound() : Results.Ok(details);
    }

    private static async Task<IResult> GetSeveritySummaryAsync(
        HttpContext httpContext,
        IncidentQueries queries,
        CancellationToken cancellationToken)
    {
        var viewer = IncidentViewer.FromPrincipal(httpContext.User);
        if (viewer is null)
        {
            return Results.Challenge();
        }

        return Results.Ok(await queries.GetSeveritySummaryAsync(viewer, cancellationToken));
    }

    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        // Tracked entity (без AsNoTracking), інакше SaveChangesAsync нічого не запише.
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        if (!(await authorizationService.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Read)).Succeeded)
        {
            return IncidentNotFound();
        }

        if (!(await authorizationService.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Update)).Succeeded)
        {
            return Results.Forbid();     // ресурс видимий (Analyst / Closed), але дія не дозволена
        }

        // Валідація контракту — ті самі правила, що в POST (ЛР 2).
        var errors = new Dictionary<string, string[]>();
        if (string.IsNullOrWhiteSpace(request.Title))
        {
            errors["title"] = ["Назва обов'язкова."];
        }
        else if (request.Title.Length > 160)
        {
            errors["title"] = ["Назва не повинна перевищувати 160 символів."];
        }

        if (string.IsNullOrWhiteSpace(request.Description))
        {
            errors["description"] = ["Опис обов'язковий."];
        }
        else if (request.Description.Length > 4000)
        {
            errors["description"] = ["Опис не повинен перевищувати 4000 символів."];
        }

        var title = request.Title?.Trim() ?? "";
        var description = request.Description?.Trim() ?? "";

        if (!errors.ContainsKey("description")
            && incident.Severity is (IncidentSeverity.High or IncidentSeverity.Critical)
            && description.Length < 40)
        {
            errors["description"] = ["Для рівнів High та Critical опис має містити щонайменше 40 символів."];
        }

        if (errors.Count == 0 && description.Equals(title, StringComparison.Ordinal))
        {
            errors["description"] = ["Опис не може повністю збігатися з назвою інциденту."];
        }

        if (errors.Count > 0)
        {
            return Results.ValidationProblem(errors);
        }

        var hasActiveDuplicate = await db.Incidents
            .AsNoTracking()
            .AnyAsync(item => item.Id != incident.Id
                              && item.Title == title
                              && (item.Status == IncidentStatus.New
                                  || item.Status == IncidentStatus.Triaged
                                  || item.Status == IncidentStatus.InProgress
                                  || item.Status == IncidentStatus.Resolved), cancellationToken);
        if (hasActiveDuplicate)
        {
            return Results.Problem(
                statusCode: StatusCodes.Status409Conflict,
                title: "Конфлікт предметного стану",
                detail: "Інцидент із такою назвою вже існує в активному статусі.");
        }

        // Змінюються ЛИШЕ content-поля; owner, status, id і час створення — серверні.
        incident.Title = title;
        incident.Description = description;
        incident.UpdatedAtUtc = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(cancellationToken);

        return Results.Ok(new IncidentListItemResponse(
            incident.Id,
            incident.Title,
            incident.Severity.ToString(),
            incident.Status.ToString(),
            incident.OccurredAtUtc,
            incident.CreatedAtUtc));
    }

    private static async Task<IResult> DeleteAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        if (!(await authorizationService.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Read)).Succeeded)
        {
            return IncidentNotFound();
        }

        if (!(await authorizationService.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Delete)).Succeeded)
        {
            return Results.Forbid();
        }

        db.Incidents.Remove(incident);
        await db.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    // Privileged transition New -> Triaged. Порядок: tracked entity -> рішення -> при deny audit і відмова
    // -> перевірка поточного статусу -> наступний статус визначає сервер -> SaveChangesAsync.
    private static async Task<IResult> TriageAsync(
        Guid id,
        TriageIncidentRequest? request,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext db,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken)
    {
        var incident = await db.Incidents.SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentNotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Read);
        var canTriage = await authorizationService.AuthorizeAsync(httpContext.User, incident, IncidentOperations.Triage);
        if (!canTriage.Succeeded)
        {
            WriteDeniedAudit(loggerFactory.CreateLogger("SecureLab.Audit"), httpContext, "incident.triage", incident.Id);
            return canRead.Succeeded ? Results.Forbid() : IncidentNotFound();
        }

        if (incident.Status != IncidentStatus.New)
        {
            return Results.Problem(
                title: "Перехід недоступний",
                detail: "Triage можливий лише зі статусу New.",
                statusCode: StatusCodes.Status409Conflict);
        }

        var actor = IncidentViewer.FromPrincipal(httpContext.User);
        if (actor is null)
        {
            return Results.Challenge();
        }

        var note = request?.Note;
        if (note is { Length: > 500 })
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["note"] = ["Примітка не повинна перевищувати 500 символів."]
            });
        }

        var now = DateTimeOffset.UtcNow;
        incident.Status = IncidentStatus.Triaged;          // наступний статус визначає сервер
        incident.UpdatedAtUtc = now;
        db.IncidentStatusHistory.Add(new IncidentStatusHistory
        {
            Id = Guid.NewGuid(),
            IncidentId = incident.Id,
            ChangedByUserId = actor.UserId,
            OldStatus = IncidentStatus.New,
            NewStatus = IncidentStatus.Triaged,
            Note = string.IsNullOrWhiteSpace(note) ? "Первинна оцінка." : note.Trim(),
            CreatedAtUtc = now
        });
        await db.SaveChangesAsync(cancellationToken);

        return Results.Ok(new TriageIncidentResponse(incident.Id, incident.Status.ToString()));
    }

    // Child resource: коментар видно лише тоді, коли видно parent incident;
    // internal comment — лише ролі з правом ReadInternalComments (Analyst).
    private static async Task<IResult> GetCommentAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext db,
        CancellationToken cancellationToken)
    {
        var comment = await db.IncidentComments
            .AsNoTracking()
            .Include(item => item.Incident)
            .Include(item => item.Author)
            .SingleOrDefaultAsync(item => item.Id == id, cancellationToken);
        if (comment is null)
        {
            return CommentNotFound();
        }

        if (!(await authorizationService.AuthorizeAsync(httpContext.User, comment.Incident, IncidentOperations.Read)).Succeeded)
        {
            return CommentNotFound();
        }

        if (comment.IsInternal
            && !(await authorizationService.AuthorizeAsync(httpContext.User, comment.Incident, IncidentOperations.ReadInternalComments)).Succeeded)
        {
            return CommentNotFound();
        }

        return Results.Ok(new IncidentCommentDetailsResponse(
            comment.Id,
            comment.IncidentId,
            comment.Author.DisplayName,
            comment.Text,
            comment.CreatedAtUtc));
    }

    // Безпечна аудиторська подія: лише перевірений subject, дія, ресурс, результат, серверний час
    // і той самий traceId, що в Problem Details. Без cookie, password, token і request body.
    private static void WriteDeniedAudit(ILogger logger, HttpContext httpContext, string action, Guid resourceId)
    {
        logger.LogWarning(
            "authorization.denied subject={SubjectId} action={Action} resource={ResourceId} "
            + "result={Result} occurredAtUtc={OccurredAtUtc:O} traceId={TraceId}",
            httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier),
            action,
            resourceId,
            "denied",
            DateTimeOffset.UtcNow,
            Activity.Current?.Id ?? httpContext.TraceIdentifier);
    }
}
