# ЛР 6, advanced variant: запуск ОДНОГО production-like екземпляра API для демонстрації Redis limiter.
# Запускайте в окремому вікні для кожного порту:
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\start-production-instance.ps1 -Port 5080
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\start-production-instance.ps1 -Port 5081
#   ... -Port 5080 -NoRedis    (контроль: Redis не налаштовано -> warning на старті, локальний limiter)
# Навчальні значення стенда (README, етап 1): БД із infra/.env.example, Redis лише на 127.0.0.1.
# Quota демонстрації 5/30 с однакова на обох екземплярах (за замовчуванням у appsettings — 20/60 с).
param(
    [int]$Port = 5080,
    [switch]$NoRedis,
    [string]$Redis = "127.0.0.1:6379",
    [int]$PermitLimit = 5,
    [int]$WindowSeconds = 30
)

$ErrorActionPreference = "Stop"
if (-not (Test-Path global.json)) { throw "Run from SecureLab root." }

$db = "Host=127.0.0.1;Port=54329;Database=securelab;Username=securelab"
$db = "$db;Password=local-study-password;Include Error Detail=false"

$env:ASPNETCORE_ENVIRONMENT = "Production"
$env:ASPNETCORE_URLS = "http://localhost:$Port"
$env:ConnectionStrings__SecureLab = $db
$env:RateLimit__Search__PermitLimit = "$PermitLimit"
$env:RateLimit__Search__WindowSeconds = "$WindowSeconds"
if ($NoRedis) {
    Remove-Item Env:RateLimit__Search__Redis__ConnectionString -ErrorAction SilentlyContinue
} else {
    $env:RateLimit__Search__Redis__ConnectionString = $Redis
}

try {
    dotnet run --project src/SecureLab.Api --no-launch-profile -c Release --no-build
} finally {
    Remove-Item Env:ASPNETCORE_ENVIRONMENT, Env:ASPNETCORE_URLS, Env:ConnectionStrings__SecureLab,
        Env:RateLimit__Search__PermitLimit, Env:RateLimit__Search__WindowSeconds,
        Env:RateLimit__Search__Redis__ConnectionString -ErrorAction SilentlyContinue
}
