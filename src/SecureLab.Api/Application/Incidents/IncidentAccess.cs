using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

// ЛР 4: ЄДИНЕ місце правил доступу до Incident (матриця docs/access-matrix.md).
//   Read                 — власник або Analyst;
//   ReadInternalComments — лише Analyst (після доступу до parent incident);
//   Update (content)     — лише власник і лише поки статус не Closed;
//   Delete               — лише власник і лише у статусі New;
//   Triage (New→Triaged) — лише Analyst; допустимість поточного статусу перевіряє endpoint.
// Administrator не має автоматичного обходу: прав, не названих у предметному правилі 2-A, роль не дає.
public static class IncidentOperations
{
    public static readonly OperationAuthorizationRequirement Read = new() { Name = nameof(Read) };
    public static readonly OperationAuthorizationRequirement ReadInternalComments = new() { Name = nameof(ReadInternalComments) };
    public static readonly OperationAuthorizationRequirement Update = new() { Name = nameof(Update) };
    public static readonly OperationAuthorizationRequirement Delete = new() { Name = nameof(Delete) };
    public static readonly OperationAuthorizationRequirement Triage = new() { Name = nameof(Triage) };
}

// Перевірений суб'єкт: id і роль беруться ТІЛЬКИ з principal (cookie, сформована сервером при login).
public sealed record IncidentViewer(Guid UserId, bool IsAnalyst)
{
    public static IncidentViewer? FromPrincipal(ClaimsPrincipal user)
    {
        var userIdValue = user.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(userIdValue, out var userId)
            ? new IncidentViewer(userId, user.IsInRole(DbSeeder.AnalystRole))
            : null;
    }
}

// Query scoping для множин (list, search, severity-summary): те саме правило, що Read у handler.
public static class IncidentVisibility
{
    public static IQueryable<Incident> VisibleTo(this IQueryable<Incident> query, IncidentViewer viewer)
    {
        var userId = viewer.UserId;
        var isAnalyst = viewer.IsAnalyst;
        return query.Where(incident => isAnalyst || incident.OwnerUserId == userId);
    }
}

// Resource-based handler: principal + конкретний завантажений Incident + операція.
public sealed class IncidentAuthorizationHandler
    : AuthorizationHandler<OperationAuthorizationRequirement, Incident>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        Incident resource)
    {
        var viewer = IncidentViewer.FromPrincipal(context.User);
        if (viewer is null)
        {
            return Task.CompletedTask;
        }

        var isOwner = resource.OwnerUserId == viewer.UserId;
        var allowed = requirement.Name switch
        {
            nameof(IncidentOperations.Read) => isOwner || viewer.IsAnalyst,
            nameof(IncidentOperations.ReadInternalComments) => viewer.IsAnalyst,
            nameof(IncidentOperations.Update) => isOwner && resource.Status != IncidentStatus.Closed,
            nameof(IncidentOperations.Delete) => isOwner && resource.Status == IncidentStatus.New,
            nameof(IncidentOperations.Triage) => viewer.IsAnalyst,
            _ => false
        };

        if (allowed)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}
