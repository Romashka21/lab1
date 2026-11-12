using System.Net.Http.Json;

namespace SecureLab.Api.Tests;

// ЛР 6: same-origin видача request token тим самим cookie-клієнтом і header для його наступних запитів.
// Викликається ЯВНО після LoginAsync лише там, де тест виконує дозволену mutation;
// негативні сценарії REG-CSRF-01 цей метод навмисно не викликають.
public static class AntiforgeryTestExtensions
{
    public const string TokenRoute = "/api/auth/csrf-token";
    public const string HeaderName = "X-SecureLab-CSRF";

    private sealed record TokenResponse(string Token);

    public static async Task UseAntiforgeryTokenAsync(
        this HttpClient client, string tokenRoute = TokenRoute, string headerName = HeaderName)
    {
        client.DefaultRequestHeaders.Remove(headerName);
        using var response = await client.GetAsync(tokenRoute);
        response.EnsureSuccessStatusCode();
        var body = await response.Content.ReadFromJsonAsync<TokenResponse>();
        if (string.IsNullOrWhiteSpace(body?.Token))
        {
            throw new InvalidOperationException("Missing request token.");
        }

        client.DefaultRequestHeaders.Add(headerName, body.Token);
    }

    // Login + токен для клієнта, який далі виконує дозволені mutations.
    public static async Task<HttpClient> LoginWithCsrfAsync(
        this Microsoft.AspNetCore.Mvc.Testing.WebApplicationFactory<Program> factory,
        string userName,
        string password)
    {
        var client = await factory.LoginAsync(userName, password);
        await client.UseAntiforgeryTokenAsync();
        return client;
    }
}
