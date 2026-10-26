namespace SecureLab.Api.Presentation.Contracts;

// ЛР 4 — VULNERABLE-стан (навмисно, лише для локального PoC).
// Звичайний update приймає ще й Status — protected server-managed поле (overposting / вертикальне підвищення).
public sealed record UpdateIncidentRequest(
    string? Title,
    string? Description,
    string? Status);

public sealed record TriageIncidentRequest(string? Note);

public sealed record TriageIncidentResponse(Guid Id, string Status);

public sealed record IncidentCommentDetailsResponse(
    Guid Id,
    Guid IncidentId,
    string AuthorDisplayName,
    string Text,
    DateTimeOffset CreatedAtUtc);
