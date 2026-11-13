# ЛР 6, advanced variant: ручна демонстрація Redis search limiter на ДВОХ production-like екземплярах
# (http://localhost:5080 і http://localhost:5081, той самий Redis і та сама БД).
#
# Використання (з кореня SecureLab, у вікні, де задано $env:SeedUsers__Password):
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\redis-search-demo.ps1 -Scenario shared
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\redis-search-demo.ps1 -Scenario outage
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\redis-search-demo.ps1 -Scenario recovery
#
# Значення cookie й пароля не друкуються. Для доказу ОКРЕМОГО входу на кожному екземплярі
# виводиться лише короткий відбиток (перші 8 hex SHA-256) cookie — за ним значення не відновити.
# Cookie передається вручну (UseCookies=false), бо production-cookie має прапорець Secure,
# а демонстрація йде локальним HTTP.
param(
    [ValidateSet("shared", "outage", "recovery")]
    [string]$Scenario = "shared",
    [int]$PortA = 5080,
    [int]$PortB = 5081
)

$ErrorActionPreference = "Stop"
if (-not $env:SeedUsers__Password) { throw "Set SeedUsers__Password in this terminal." }

Add-Type -AssemblyName System.Net.Http
$handler = New-Object System.Net.Http.HttpClientHandler
$handler.UseCookies = $false
$handler.AllowAutoRedirect = $false
$http = New-Object System.Net.Http.HttpClient($handler)

function Send-Request([string]$Method, [string]$Url, [string]$Cookie, [string]$Json) {
    $request = New-Object System.Net.Http.HttpRequestMessage([System.Net.Http.HttpMethod]::new($Method), $Url)
    if ($Cookie) { [void]$request.Headers.TryAddWithoutValidation("Cookie", $Cookie) }
    if ($Json) { $request.Content = New-Object System.Net.Http.StringContent($Json, [Text.Encoding]::UTF8, "application/json") }
    return $http.SendAsync($request).GetAwaiter().GetResult()
}

function Get-Fingerprint([string]$Value) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $bytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Value))
    return (($bytes[0..3] | ForEach-Object { $_.ToString("x2") }) -join "")
}

function Login([int]$Port, [string]$User) {
    $json = @{ userName = $User; password = $env:SeedUsers__Password } | ConvertTo-Json -Compress
    $response = Send-Request "POST" "http://localhost:$Port/api/auth/login" $null $json
    $setCookie = $null
    if ($response.Headers.Contains("Set-Cookie")) {
        $setCookie = $response.Headers.GetValues("Set-Cookie") |
            Where-Object { $_ -like ".AspNetCore.Identity.Application=*" } | Select-Object -First 1
    }
    if (-not $setCookie) { throw "Login $User @ $Port failed: $([int]$response.StatusCode)" }
    $cookie = ($setCookie -split ";")[0]
    Write-Host ("login  {0,-5} @ {1}: {2}  cookie#{3}" -f $User, $Port, [int]$response.StatusCode, (Get-Fingerprint $cookie))
    return $cookie
}

function Search([string]$Label, [int]$Port, [string]$Cookie) {
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $response = Send-Request "GET" "http://localhost:$Port/api/incidents/search?q=USB" $Cookie $null
    $watch.Stop()
    $retry = "-"
    if ($response.Headers.RetryAfter -and $null -ne $response.Headers.RetryAfter.Delta) {
        $retry = [int]$response.Headers.RetryAfter.Delta.TotalSeconds
    }
    Write-Host ("search {0,-5} @ {1}: {2}  Retry-After={3,-3} {4,5} ms" -f $Label, $Port, [int]$response.StatusCode, $retry, $watch.ElapsedMilliseconds)
}

switch ($Scenario) {
    "shared" {
        Write-Host "== Shared state: окремий вхід Alice на $PortA і $PortB, квота 5 сумарна =="
        $aliceA = Login $PortA "alice"
        $aliceB = Login $PortB "alice"
        $bobB = Login $PortB "bob"
        1..3 | ForEach-Object { Search "alice" $PortA $aliceA }
        1..2 | ForEach-Object { Search "alice" $PortB $aliceB }
        Write-Host "-- шостий запит Alice: 429 на обох екземплярах; Bob — окремий partition --"
        Search "alice" $PortA $aliceA
        Search "alice" $PortB $aliceB
        Search "bob" $PortB $bobB
    }
    "outage" {
        Write-Host "== Redis зупинено: локальний limiter екземпляра $PortA, пошук без очікування таймауту =="
        $aliceA = Login $PortA "alice"
        1..7 | ForEach-Object { Search "alice" $PortA $aliceA }
    }
    "recovery" {
        Write-Host "== Redis знову запущено: лічильник знову спільний =="
        $aliceA = Login $PortA "alice"
        $aliceB = Login $PortB "alice"
        Search "alice" $PortA $aliceA
        Search "alice" $PortB $aliceB
    }
}
