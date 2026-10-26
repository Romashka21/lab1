using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using SecureLab.Api.Presentation.Contracts;

namespace SecureLab.Api.Application.Incidents;

public sealed class IncidentQueries(SecureLabDbContext dbContext, ILogger<IncidentQueries> logger)
{
    // ЛР 4: список обмежено дозволеною множиною (owner або Analyst) прямо в SQL-запиті.
    public async Task<IReadOnlyList<IncidentListItemResponse>> GetListAsync(
        IncidentStatus? status,
        IncidentViewer viewer,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incidents with status filter {Status}", status);

        var query = dbContext.Incidents
            .AsNoTracking()
            .VisibleTo(viewer);

        if (status is not null)
        {
            query = query.Where(incident => incident.Status == status);
        }

        return await query
            .OrderByDescending(incident => incident.CreatedAtUtc)
            .Select(incident => new IncidentListItemResponse(
                incident.Id,
                incident.Title,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc))
            .ToListAsync(cancellationToken);
    }

    // ЛР 4: entity лише для серверного рішення handler-а; OwnerUserId не потрапляє у response DTO.
    public Task<Incident?> FindForDecisionAsync(Guid id, CancellationToken cancellationToken) =>
        dbContext.Incidents
            .AsNoTracking()
            .SingleOrDefaultAsync(incident => incident.Id == id, cancellationToken);

    // Викликається ЛИШЕ після дозволу Read. Видимість internal comment передає endpoint
    // з рішення ReadInternalComments для поточного principal.
    public Task<IncidentDetailsResponse?> GetDetailsAsync(
        Guid id,
        bool includeInternalComments,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Loading incident {IncidentId}", id);

        return dbContext.Incidents
            .AsNoTracking()
            .Where(incident => incident.Id == id)
            .Select(incident => new IncidentDetailsResponse(
                incident.Id,
                incident.Title,
                incident.Description,
                incident.Severity.ToString(),
                incident.Status.ToString(),
                incident.OccurredAtUtc,
                incident.CreatedAtUtc,
                incident.Owner.DisplayName,
                incident.Comments
                    .Where(comment => includeInternalComments || !comment.IsInternal)
                    .OrderBy(comment => comment.CreatedAtUtc)
                    .Select(comment => new IncidentCommentResponse(
                        comment.Id,
                        comment.Author.DisplayName,
                        comment.Text,
                        comment.CreatedAtUtc))
                    .ToList()))
            .SingleOrDefaultAsync(cancellationToken);
    }

    // ЛР 4 (A-11): агрегація лише по дозволеній множині — фільтр стоїть ДО GroupBy.
    public async Task<IReadOnlyList<IncidentSeveritySummaryResponse>> GetSeveritySummaryAsync(
        IncidentViewer viewer,
        CancellationToken cancellationToken)
    {
        logger.LogInformation("Calculating incident severity summary");

        var groupedData = await dbContext.Incidents
            .AsNoTracking()
            .VisibleTo(viewer)
            .GroupBy(incident => incident.Severity)
            .Select(group => new
            {
                Severity = group.Key,
                Count = group.Count()
            })
            .OrderBy(item => item.Severity)
            .ToListAsync(cancellationToken);

        var summary = groupedData
            .Select(item => new IncidentSeveritySummaryResponse(
                item.Severity.ToString(),
                item.Count))
            .ToList();

        logger.LogInformation("Calculated summary with {GroupCount} groups", summary.Count);

        return summary;
    }
}
