using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using SecureLab.Api.Data;
using SecureLab.Api.Infrastructure.RateLimiting;
using StackExchange.Redis;

namespace SecureLab.Api.Tests;

// ЛР 6, advanced variant (погоджено): Redis search limiter.
//   REG-REDIS-01 — живий Redis: два екземпляри (два host), окремий вхід Alice на кожному,
//                  3 + 2 -> 200, далі 429 на обох; Bob — окремий partition; ключ/значення/TTL у Redis;
//   REG-REDIS-02 — вікно відлічується від першого запиту й після TTL квота відновлюється;
//   REG-REDIS-03 — недоступний Redis: не 500, локальний limiter дає 429 після quota,
//                  лише одна спроба звернення до Redis за паузу, один warning на відмову.
// Передумова для 01/02: docker start securelab-redis (або SECURELAB_TEST_REDIS=host:port).
public sealed class Lab06RedisRateLimitTests(SecureLabApiFactory factory) : IClassFixture<SecureLabApiFactory>
{
    private const string Search = "/api/incidents/search?q=USB";

    private static string SeedPassword => Lab06TestData.SeedPassword;

    private static string RedisAddress =>
        Environment.GetEnvironmentVariable("SECURELAB_TEST_REDIS") ?? "127.0.0.1:6379";

    private static string NewPrefix() => $"securelab:test:{Guid.NewGuid():N}:";

    private static string KeyFor(string prefix, Guid userId) => prefix + "user:" + userId.ToString("D");

    // «Екземпляр API» = окремий host зі своїм in-memory станом; спільне між ними лише Redis.
    private WebApplicationFactory<Program> Instance(
        string redis, string prefix, int permit, int windowSeconds, ILoggerProvider? logs = null) =>
        factory.WithWebHostBuilder(builder =>
        {
            builder.UseSetting("RateLimit:Search:Redis:ConnectionString", redis);
            builder.UseSetting("RateLimit:Search:Redis:KeyPrefix", prefix);
            builder.UseSetting("RateLimit:Search:Redis:ReconnectPauseSeconds", "30");
            builder.UseSetting("RateLimit:Search:PermitLimit", permit.ToString(CultureInfo.InvariantCulture));
            builder.UseSetting("RateLimit:Search:WindowSeconds", windowSeconds.ToString(CultureInfo.InvariantCulture));
            if (logs is not null)
            {
                builder.ConfigureLogging(logging => logging.AddProvider(logs));
            }
        });

    private static readonly HttpStatusCode[] ExpectedFallbackStatuses =
    [
        HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.OK,
        HttpStatusCode.TooManyRequests, HttpStatusCode.TooManyRequests
    ];

    private static IDatabase LiveRedis(ConnectionMultiplexer connection)
    {
        Assert.True(connection.IsConnected,
            $"Redis {RedisAddress} недоступний: запустіть docker start securelab-redis.");
        return connection.GetDatabase();
    }

    [Fact]
    public async Task RegRedis01_TwoInstances_SeparateLogins_ShareCounter_IsolatePartitions_StoreOnlyCounterWithTtl()
    {
        var prefix = NewPrefix();
        using var connection = await ConnectionMultiplexer.ConnectAsync(RedisAddress + ",abortConnect=false,connectTimeout=2000");
        var redis = LiveRedis(connection);
        try
        {
            using var instanceA = Instance(RedisAddress, prefix, permit: 5, windowSeconds: 30);
            using var instanceB = Instance(RedisAddress, prefix, permit: 5, windowSeconds: 30);

            // Окремий вхід на кожному екземплярі: різні auth-cookie, той самий користувач.
            using var aliceA = await instanceA.LoginAsync("alice", SeedPassword);
            using var aliceB = await instanceB.LoginAsync("alice", SeedPassword);
            using var bobB = await instanceB.LoginAsync("bob", SeedPassword);

            for (var attempt = 0; attempt < 3; attempt++)
            {
                using var allowed = await aliceA.GetAsync(Search);
                Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
            }

            for (var attempt = 0; attempt < 2; attempt++)
            {
                using var allowed = await aliceB.GetAsync(Search);
                Assert.Equal(HttpStatusCode.OK, allowed.StatusCode);
            }

            // Квота 5 вичерпана сумарно на двох екземплярах -> 429 на обох, формат як у локального limiter.
            using var limitedA = await aliceA.GetAsync(Search);
            using var limitedB = await aliceB.GetAsync(Search);
            foreach (var limited in new[] { limitedA, limitedB })
            {
                Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode);
                Assert.Equal("application/problem+json", limited.Content.Headers.ContentType?.MediaType);
                var retryAfter = limited.Headers.RetryAfter?.Delta;
                Assert.NotNull(retryAfter);
                Assert.InRange(retryAfter.Value, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(30));
            }

            // Інший partition (Bob) на тому самому екземплярі не зачеплено.
            using var bob = await bobB.GetAsync(Search);
            Assert.Equal(HttpStatusCode.OK, bob.StatusCode);

            // У Redis: ключ лише з id користувача, значення — ціле число, TTL у межах вікна.
            var aliceKey = KeyFor(prefix, DbSeeder.AliceId);
            Assert.Equal(7L, (long)await redis.StringGetAsync(aliceKey));
            var ttl = await redis.KeyTimeToLiveAsync(aliceKey);
            Assert.NotNull(ttl);
            Assert.InRange(ttl.Value, TimeSpan.FromMilliseconds(1), TimeSpan.FromSeconds(30));
            Assert.Equal(1L, (long)await redis.StringGetAsync(KeyFor(prefix, DbSeeder.BobId)));
        }
        finally
        {
            await redis.KeyDeleteAsync([KeyFor(prefix, DbSeeder.AliceId), KeyFor(prefix, DbSeeder.BobId)]);
        }
    }

    [Fact]
    public async Task RegRedis02_WindowStartsAtFirstRequest_AndQuotaRecoversAfterTtl()
    {
        var prefix = NewPrefix();
        using var connection = await ConnectionMultiplexer.ConnectAsync(RedisAddress + ",abortConnect=false,connectTimeout=2000");
        var redis = LiveRedis(connection);
        try
        {
            using var instance = Instance(RedisAddress, prefix, permit: 2, windowSeconds: 2);
            using var alice = await instance.LoginAsync("alice", SeedPassword);

            using (var first = await alice.GetAsync(Search)) { Assert.Equal(HttpStatusCode.OK, first.StatusCode); }
            using (var second = await alice.GetAsync(Search)) { Assert.Equal(HttpStatusCode.OK, second.StatusCode); }
            using (var limited = await alice.GetAsync(Search)) { Assert.Equal(HttpStatusCode.TooManyRequests, limited.StatusCode); }

            await Task.Delay(TimeSpan.FromSeconds(2.5));   // TTL ключа минув -> нове вікно з наступного запиту
            Assert.False(await redis.KeyExistsAsync(KeyFor(prefix, DbSeeder.AliceId)));
            using var recovered = await alice.GetAsync(Search);
            Assert.Equal(HttpStatusCode.OK, recovered.StatusCode);
            Assert.Equal(1L, (long)await redis.StringGetAsync(KeyFor(prefix, DbSeeder.AliceId)));
        }
        finally
        {
            await redis.KeyDeleteAsync(KeyFor(prefix, DbSeeder.AliceId));
        }
    }

    [Fact]
    public async Task RegRedis03_RedisUnavailable_NoServerError_LocalQuotaGives429_OneAttemptPerPause_OneWarning()
    {
        var logs = new CapturingLoggerProvider();
        // 127.0.0.1:6390 — навмисно недосяжний порт: Redis «зупинено».
        using var instance = Instance("127.0.0.1:6390", NewPrefix(), permit: 3, windowSeconds: 30, logs);
        using var alice = await instance.LoginAsync("alice", SeedPassword);
        var store = instance.Services.GetRequiredService<RedisSearchQuotaStore>();

        var statuses = new List<HttpStatusCode>();
        var durations = new List<TimeSpan>();
        for (var attempt = 0; attempt < 5; attempt++)
        {
            var stopwatch = Stopwatch.StartNew();
            using var response = await alice.GetAsync(Search);
            durations.Add(stopwatch.Elapsed);
            statuses.Add(response.StatusCode);
            if (response.StatusCode == HttpStatusCode.TooManyRequests)
            {
                Assert.NotNull(response.Headers.RetryAfter);
            }
        }

        // Не 500; локальний limiter цього екземпляра тримає ту саму quota.
        Assert.Equal(ExpectedFallbackStatuses, statuses);

        // Пауза перед повторним підключенням: до Redis звернувся лише перший запит,
        // решта йшли одразу на локальний limiter і не чекали таймауту.
        Assert.Equal(1L, store.RedisAttempts);
        Assert.All(durations.Skip(1), duration => Assert.True(duration < TimeSpan.FromSeconds(1), $"Запит тривав {duration}."));

        // Один warning на одну відмову, без connection string.
        var warnings = logs.Entries
            .Where(entry => entry.Category == "SecureLab.RedisSearchLimiter" && entry.Level == LogLevel.Warning)
            .ToList();
        Assert.Single(warnings);
        Assert.DoesNotContain("6390", warnings[0].Message, StringComparison.Ordinal);
    }

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly ConcurrentQueue<(string Category, LogLevel Level, string Message)> _entries = new();

        public IReadOnlyList<(string Category, LogLevel Level, string Message)> Entries => _entries.ToArray();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, _entries);

        public void Dispose()
        {
        }

        private sealed class CapturingLogger(
            string category,
            ConcurrentQueue<(string Category, LogLevel Level, string Message)> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter) =>
                entries.Enqueue((category, logLevel, formatter(state, exception)));
        }
    }
}
