using System.Diagnostics;
using System.Threading.RateLimiting;
using StackExchange.Redis;

namespace SecureLab.Api.Infrastructure.RateLimiting;

// ЛР 6, advanced variant (погоджено викладачем): спільний між екземплярами API лічильник
// для policy "search". Вмикається конфігурацією RateLimit:Search:Redis:ConnectionString у будь-якому
// профілі. У Redis зберігається лише число запитів і TTL; ключ містить тільки id користувача.
public sealed class RedisSearchLimiterOptions
{
    public string? ConnectionString { get; set; }
    public string KeyPrefix { get; set; } = "securelab:rl:search:";
    public int ReconnectPauseSeconds { get; set; } = 10;
    public int TimeoutMilliseconds { get; set; } = 500;

    public bool Enabled => !string.IsNullOrWhiteSpace(ConnectionString);
}

// Спільний для всіх partitions стан: одне з'єднання та circuit breaker.
public sealed class RedisSearchQuotaStore : IDisposable
{
    // Вікно відлічується від ПЕРШОГО запиту partition: INCR, і лише для значення 1 — PEXPIRE.
    // Годинник екземплярів API не використовується, тож розбіжність часу між ними не розносить
    // запити в різні ключі; «3 + 2» не розривається межею вікна, поки ключ живий.
    // Захист: якщо ключ із якоїсь причини не має TTL, він одержує TTL тут же (атомарно в Lua).
    private const string Script = """
        local current = redis.call('INCR', KEYS[1])
        if current == 1 then
          redis.call('PEXPIRE', KEYS[1], ARGV[1])
        end
        local ttl = redis.call('PTTL', KEYS[1])
        if ttl < 0 then
          redis.call('PEXPIRE', KEYS[1], ARGV[1])
          ttl = tonumber(ARGV[1])
        end
        return { current, ttl }
        """;

    private readonly RedisSearchLimiterOptions _options;
    private readonly ConfigurationOptions? _configuration;
    private readonly ILogger _logger;
    private readonly Lock _connectionGate = new();
    private ConnectionMultiplexer? _connection;
    private long _pausedUntil;   // Environment.TickCount64; 0 = пауза не діє
    private int _outage;         // 0 = Redis доступний, 1 = відмова (warning уже записано)
    private long _attempts;      // скільки разів запит пошуку справді звертався до Redis

    // Конфігурація читається з DI (остаточна конфігурація застосунку, включно зі змінними
    // середовища й тестовими перевизначеннями), а не з builder до Build().
    public RedisSearchQuotaStore(IConfiguration configuration, ILoggerFactory loggerFactory)
    {
        var options = configuration.GetSection("RateLimit:Search:Redis").Get<RedisSearchLimiterOptions>()
            ?? new RedisSearchLimiterOptions();
        _options = options;
        _logger = loggerFactory.CreateLogger("SecureLab.RedisSearchLimiter");
        if (options.Enabled)
        {
            // Помилка формату конфігурації має бути видна на старті, а не як 500 під час пошуку.
            _configuration = ConfigurationOptions.Parse(options.ConnectionString!);
            _configuration.AbortOnConnectFail = false;   // не падати на старті; перепідключення у фоні
            _configuration.ConnectTimeout = options.TimeoutMilliseconds;
            _configuration.SyncTimeout = options.TimeoutMilliseconds;
            _configuration.AsyncTimeout = options.TimeoutMilliseconds;
            _configuration.ConnectRetry = 1;
        }
    }

    public bool Enabled => _options.Enabled;

    public string KeyPrefix => _options.KeyPrefix;

    public int ReconnectPauseSeconds => _options.ReconnectPauseSeconds;

    // Для регресії паузи: під час паузи це число не зростає.
    public long RedisAttempts => Interlocked.Read(ref _attempts);

    // Повертає (лічильник, залишок вікна) або null, якщо Redis зараз недоступний (тоді — fallback).
    public async Task<(long Count, TimeSpan Remaining)?> TryCountAsync(string partition, TimeSpan window)
    {
        // Пауза перед повторним підключенням: поки вона діє, запит пошуку взагалі не звертається
        // до Redis і не чекає таймауту.
        if (Environment.TickCount64 < Interlocked.Read(ref _pausedUntil))
        {
            return null;
        }

        Interlocked.Increment(ref _attempts);
        try
        {
            var database = GetConnection().GetDatabase();
            var raw = await database.ScriptEvaluateAsync(
                Script,
                [new RedisKey(_options.KeyPrefix + partition)],
                [(long)window.TotalMilliseconds]);
            var values = (RedisResult[]?)raw ?? throw new RedisException("Unexpected script result.");
            var count = (long)values[0];
            var remaining = TimeSpan.FromMilliseconds(Math.Max(0, (long)values[1]));

            if (Interlocked.Exchange(ref _outage, 0) == 1)
            {
                _logger.LogInformation(
                    "Redis search limiter: з'єднання відновлено, лічильник пошуку знову спільний між екземплярами.");
            }

            return (count, remaining);
        }
        catch (Exception exception) when (exception is RedisException or TimeoutException or ObjectDisposedException)
        {
            Interlocked.Exchange(
                ref _pausedUntil,
                Environment.TickCount64 + (_options.ReconnectPauseSeconds * 1000L));

            // Один warning на одну відмову (перехід «доступний -> недоступний»), без connection string
            // і без тексту винятку (він може містити адресу/параметри з'єднання).
            if (Interlocked.Exchange(ref _outage, 1) == 0)
            {
                _logger.LogWarning(
                    "Redis search limiter недоступний ({ErrorType}); тимчасово діє локальний limiter цього "
                    + "екземпляра. Повторна спроба підключення не раніше ніж через {PauseSeconds} с.",
                    exception.GetType().Name,
                    _options.ReconnectPauseSeconds);
            }

            return null;
        }
    }

    private ConnectionMultiplexer GetConnection()
    {
        if (_connection is not null)
        {
            return _connection;
        }

        lock (_connectionGate)
        {
            if (_connection is null)
            {
                _connection = ConnectionMultiplexer.Connect(
                    _configuration ?? throw new InvalidOperationException("Redis search limiter is not configured."));
            }

            return _connection;
        }
    }

    public void Dispose() => _connection?.Dispose();
}

// Limiter однієї partition (одного користувача). Вбудований у наявний AddRateLimiter як фабрика
// policy "search": відмова йде через той самий options.OnRejected (Problem Details + Retry-After).
public sealed class RedisFixedWindowSearchLimiter : RateLimiter
{
    private readonly RedisSearchQuotaStore _store;
    private readonly string _partition;
    private readonly int _permitLimit;
    private readonly TimeSpan _window;
    private readonly FixedWindowRateLimiter _local;   // fallback на час недоступності Redis
    private long _lastUsed = Stopwatch.GetTimestamp();

    public RedisFixedWindowSearchLimiter(RedisSearchQuotaStore store, string partition, int permitLimit, TimeSpan window)
    {
        _store = store;
        _partition = partition;
        _permitLimit = permitLimit;
        _window = window;
        _local = new FixedWindowRateLimiter(new FixedWindowRateLimiterOptions
        {
            PermitLimit = permitLimit,
            Window = window,
            QueueLimit = 0
        });
    }

    public override TimeSpan? IdleDuration => Stopwatch.GetElapsedTime(Interlocked.Read(ref _lastUsed));

    public override RateLimiterStatistics? GetStatistics() => _local.GetStatistics();

    // Синхронного рішення немає (потрібен мережевий виклик): middleware після невдалої спроби
    // викликає AcquireAsync, де й виконується перевірка. Тут лічильник не змінюється.
    protected override RateLimitLease AttemptAcquireCore(int permitCount) => QuotaLease.NotDecided;

    protected override async ValueTask<RateLimitLease> AcquireAsyncCore(int permitCount, CancellationToken cancellationToken)
    {
        Interlocked.Exchange(ref _lastUsed, Stopwatch.GetTimestamp());

        var shared = await _store.TryCountAsync(_partition, _window);
        if (shared is { } decision)
        {
            return decision.Count <= _permitLimit
                ? QuotaLease.Acquired
                : new QuotaLease(false, decision.Remaining);
        }

        // Redis недоступний: той самий quota, але лічильник лише цього екземпляра (residual risk).
        return await _local.AcquireAsync(permitCount, cancellationToken);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _local.Dispose();
        }

        base.Dispose(disposing);
    }

    private sealed class QuotaLease(bool isAcquired, TimeSpan? retryAfter) : RateLimitLease
    {
        public static readonly QuotaLease Acquired = new(true, null);
        public static readonly QuotaLease NotDecided = new(false, null);

        public override bool IsAcquired { get; } = isAcquired;

        public override IEnumerable<string> MetadataNames =>
            retryAfter is null ? Array.Empty<string>() : new[] { MetadataName.RetryAfter.Name };

        public override bool TryGetMetadata(string metadataName, out object? metadata)
        {
            if (retryAfter is { } value && metadataName == MetadataName.RetryAfter.Name)
            {
                // Retry-After не менше 1 с, щоб клієнт не повторював миттєво.
                metadata = value < TimeSpan.FromSeconds(1) ? TimeSpan.FromSeconds(1) : value;
                return true;
            }

            metadata = null;
            return false;
        }
    }
}
