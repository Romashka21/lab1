using System.Net.Http.Json;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SecureLab.Api.Tests;

public static class CookieClient
{
    // ЛР 6: тип параметра розширено до WebApplicationFactory<Program>, щоб той самий login працював
    // і для похідного Production-host (WithWebHostBuilder). SecureLabApiFactory успадковує цей тип.
    public static async Task<HttpClient> LoginAsync(this WebApplicationFactory<Program> factory, string userName, string password)
    {
        var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"), AllowAutoRedirect = false, HandleCookies = true
        });
        using var response = await client.PostAsJsonAsync("/api/auth/login", new { userName, password });
        if (!response.IsSuccessStatusCode)
        {
            client.Dispose();
            throw new InvalidOperationException("Study login failed (credentials omitted).");
        }
        return client;
    }
}
