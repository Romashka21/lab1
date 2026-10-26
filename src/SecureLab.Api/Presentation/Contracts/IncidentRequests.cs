using System.Text.Json.Serialization;

namespace SecureLab.Api.Presentation.Contracts;

// ЛР 4: межа довіри. Звичайний update приймає ЛИШЕ content-поля.
// OwnerUserId, Status, Role, Id у контракті відсутні; будь-яке зайве поле -> 400 (контракт A-08b).
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record UpdateIncidentRequest(
    string? Title,
    string? Description);

// Privileged transition: клієнт може передати лише примітку; наступний статус визначає сервер.
[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
public sealed record TriageIncidentRequest(string? Note);

public sealed record TriageIncidentResponse(Guid Id, string Status);

public sealed record IncidentCommentDetailsResponse(
    Guid Id,
    Guid IncidentId,
    string AuthorDisplayName,
    string Text,
    DateTimeOffset CreatedAtUtc);
