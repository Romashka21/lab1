using System.Net;
using System.Net.Http.Json;
using SecureLab.Api.Data;
using SecureLab.Api.Scaffolding;

namespace SecureLab.Api.Tests;

// ЛР 6, REG-F03-01: перевірка дубліката назви (T-03) виконується лише серед інцидентів власника
// і не розкриває існування чужого інциденту через 409.
public sealed class Lab06DuplicateTitleTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private static string SeedPassword => Lab06TestData.SeedPassword;

    // ------------------------------------------------------------------ REG-F03-01 (третя finding)

    [Fact]
    public async Task RegF03_DuplicateTitleCheck_DoesNotRevealForeignIncident_ButKeepsOwnConflict()
    {
        const string bobActiveTitle = "Невідома спроба входу";   // seed: інцидент Bob у статусі InProgress
        var own = await Lab06TestData.InsertIncidentAsync(factory, DbSeeder.AliceId, "F03");
        Guid? created = null;
        try
        {
            using var alice = await factory.LoginWithCsrfAsync("alice", SeedPassword);

            // Створення з назвою чужого активного інциденту: відповідь не має відрізнятися
            // від звичайного створення (раніше було 409 «вже існує» = оракул існування).
            using var create = await alice.PostAsJsonAsync("/api/incidents", new
            {
                title = bobActiveTitle,
                description = "Власний запис Alice; назва збігається з чужим інцидентом.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
            });
            Assert.Equal(HttpStatusCode.Created, create.StatusCode);
            var body = await create.Content.ReadFromJsonAsync<CreatedIncidentResponse>();
            Assert.NotNull(body);
            created = body.Id;

            // Позитивна регресія правила T-03: дублікат серед ВЛАСНИХ активних інцидентів і далі 409.
            using var ownDuplicate = await alice.PostAsJsonAsync("/api/incidents", new
            {
                title = bobActiveTitle,
                description = "Повторний власний запис з тією самою назвою.",
                severity = "Low",
                occurredAtUtc = DateTimeOffset.UtcNow.AddMinutes(-5)
            });
            Assert.Equal(HttpStatusCode.Conflict, ownDuplicate.StatusCode);

            // PUT: перейменування власного інциденту на назву чужого активного — не 409.
            await Lab06TestData.DeleteIncidentsAsync(factory, body.Id);
            created = null;
            using var rename = await alice.PutAsJsonAsync(Lab06TestData.IncidentPath(own),
                Lab06TestData.UpdateBody(bobActiveTitle, "Перейменування власного запису на назву чужого інциденту."));
            Assert.Equal(HttpStatusCode.OK, rename.StatusCode);

            // Інцидент Bob не змінено.
            Assert.Equal(bobActiveTitle, (await Lab06TestData.StateAsync(factory, DbSeeder.BobIncidentId))?.Title);
        }
        finally
        {
            await Lab06TestData.DeleteIncidentsAsync(factory, own);
            if (created is Guid createdId)
            {
                await Lab06TestData.DeleteIncidentsAsync(factory, createdId);
            }
        }
    }
}
