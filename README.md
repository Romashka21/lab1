# SecureLab starter: трекер інцидентів

Це baseline starter для дисципліни «Прикладні технології програмування в
інформаційній безпеці», варіант **2-A**. Він містить один простий
трирівневий моноліт, локальний PostgreSQL, мінімальний Vanilla JavaScript
клієнт, відтворювані seed/reset і готовий `WebApplicationFactory` test harness.

Це стан системи **до ЛР 1**. Далі студент послідовно розвиває власний проєкт:
результат завершеної ЛР стає основою наступної. Якщо попередню роботу технічно
не завершено, її потрібно завершити або виправити перед переходом далі.

Starter навмисно не містить завершених рішень ЛР 1–6, автентифікації,
авторизації або навмисних уразливостей. Потрібні для конкретної роботи зміни
студент виконує у власному проєкті за методичними вказівками й лише у
дозволеному локальному середовищі.

## 1. Передумови

- .NET SDK 10, стабільний feature band `10.0.1xx` або новіший (`global.json`: `10.0.100`,
  `rollForward: latestFeature`; перевірено на `10.0.401`);
- Docker із підтримкою `docker compose`;
- Git;
- вільні локальні порти `5080` і `54329`; для advanced-сценарію ЛР 6 ще `5081` і `6379` (Redis).

Перевірте:

```bash
dotnet --version
docker --version
docker compose version
```

## 2. Перший запуск

У корені starter виконайте:

```bash
docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
dotnet tool restore
dotnet restore SecureLab.sln
dotnet run --project src/SecureLab.Api
```

Під час першого Development-запуску API застосує готову EF Core migration і
додасть фіксовані навчальні дані. Відкрийте:

- browser client: <http://localhost:5080/>;
- health/readiness: <http://localhost:5080/health>;
- інтерактивний OpenAPI: <http://localhost:5080/scalar/v1>;
- OpenAPI JSON: <http://localhost:5080/openapi/v1.json>.

Зупиніть API через `Ctrl+C`. Контейнер БД зупиняється командою:

```bash
docker compose --env-file infra/.env.example -f infra/compose.yaml down
```

## 3. Відомий початковий стан

Seed містить Alice, Bob, Morgan (Analyst) та Admin, три інциденти, два
публічні коментарі й одну зміну статусу. UUID не випадкові: їх можна
використовувати у `.http`-сценаріях і тестах.

Локальні значення `securelab / local-study-password` є лише відкритими
навчальними credentials для БД, прив'язаної до `127.0.0.1`. Це не секрет і
його заборонено повторно використовувати для іншої БД чи середовища. Реальний
connection string передавайте поза Git через `ConnectionStrings__SecureLab`.

Щоб застосувати наявні migrations, **очистити лише відомі навчальні таблиці**
локальної БД і повернути seed до відомого стану:

```bash
dotnet run --project src/SecureLab.Api -- --reset-database
```

Команда навмисно відмовляється працювати поза явно налаштованим Development
environment. Вона знищує поточні локальні навчальні дані у відомих таблицях
БД `securelab`, але не видаляє саму БД або її схему.

## 4. Перевірка

Коли PostgreSQL уже працює:

```bash
dotnet build src/SecureLab.Api/SecureLab.Api.csproj --configuration Release
dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release
```

На macOS/Linux або у Git Bash увесь сценарій підняття PostgreSQL і тестів
виконує одна команда:

```bash
bash scripts/test.sh
```

HTTP-сценарії для ручної перевірки розташовані у `tests/http/incidents.http`.
Вони охоплюють `200`, `400`, `404` та початковий `501` для точки розширення.

## 5. Завдання ЛР 1 у starter

Працюючий близький приклад — фільтр інцидентів за `status` через browser → API
→ EF Core → PostgreSQL → JSON → безпечні DOM sinks. Обмежена точка зміни —
`GET /api/incidents/severity-summary`, який у baseline повертає `501`.

Під час ЛР 1 студент реалізує підсумок кількості інцидентів за severity,
викликає endpoint із клієнта, безпечно відображає результат, додає
відтворюваний HTTP-сценарій або адаптує інтеграційний тест і доповнює
`docs/architecture.md`. Зміна схеми БД для мінімального маршруту не потрібна.

## 6. Структура

```text
src/SecureLab.Api/
  Presentation/   endpoints і зовнішні response contracts
  Application/    сценарії застосунку
  Data/           DbContext, entities, migration, seed/reset
  Client/         HTML/CSS/Vanilla JavaScript
tests/
  SecureLab.Api.Tests/   інтеграційні й security regression приклади
  http/                  ручні HTTP-сценарії
infra/                   локальний PostgreSQL
docs/                    карта архітектури, варіант, матриця доступу, звіт
```

Це не Clean/Onion Architecture, DDD, мікросервіси або вимога TDD. Каталоги
позначають відповідальність коду в одному server project.

## 7. Типові проблеми запуску

| Ознака | Перевірка |
|---|---|
| `connection refused` до PostgreSQL | `docker compose ... ps`, порт `54329`, стан healthcheck |
| SDK не знайдено | `dotnet --version` у цій директорії має повернути стабільну `10.0.*` не нижче `10.0.100` |
| порт API зайнятий | зупиніть інший процес на `5080` або задайте `ASPNETCORE_URLS` |
| migration не застосовується | перевірте `ASPNETCORE_ENVIRONMENT=Development` і connection string |
| змінили credentials у compose | узгоджено перевизначте `ConnectionStrings__SecureLab`; не записуйте реальне значення до Git |

Перед commit перегляньте `git status`, `git diff --staged` і переконайтеся, що
до Git не потрапили `.env`, cookies, tokens, реальні passwords, dumps або logs.

## 8. ЛР 6: hardening, security review і регресія (`v1.0.0`)

Документи огляду: `docs/security-review.md`, `docs/threat-model.md`, `docs/findings/F-0*.md`,
погодження advanced variant — `docs/evidence/lab06-redis-approval.md`.

### Пароль seed і заборони

Пароль навчальних акаунтів задавайте лише в поточному вікні PowerShell і не друкуйте:

```powershell
$secure = Read-Host "Seed password" -AsSecureString
$env:SeedUsers__Password = [System.Net.NetworkCredential]::new("", $secure).Password
Remove-Variable secure
$env:SeedUsers__Password.Length
```

До Git, звітів і скріншотів не потрапляють паролі, значення cookie
(`.AspNetCore.Identity.Application`, `SecureLab.Antiforgery`), значення header
`X-SecureLab-CSRF`, журнали API й реальні connection strings.

### Antiforgery (CSRF)

Кожна cookie-authenticated мутація (`POST/PUT/DELETE /api/incidents…`, `POST …/triage`,
`POST /api/auth/logout`) вимагає header `X-SecureLab-CSRF` з токеном від
`GET /api/auth/csrf-token` (лише після входу). Без валідної пари — `400` Problem Details.
Сторінки клієнта підключають `Client/csrf.js` і роблять мутації через
`window.SecureLabCsrf.mutate(url, options)`; власні сторінки мають робити так само.
Login і register токена не потребують.

### Redis для спільного search limiter (advanced variant)

```powershell
docker run -d --name securelab-redis -p 127.0.0.1:6379:6379 redis:7.4-alpine
docker exec securelab-redis redis-cli PING
```

API вмикає Redis у будь-якому профілі, якщо задано
`RateLimit__Search__Redis__ConnectionString` (наприклад, `127.0.0.1:6379`); без нього на старті
пишеться warning і діє локальний limiter. Quota — `RateLimit:Search:PermitLimit` /
`WindowSeconds` (`appsettings.json`: 20 за 60 с). Якщо Redis недоступний, API не повертає 500:
тимчасово діє локальний limiter тієї самої quota, один warning на відмову, info при відновленні.

Демонстрація на двох production-like екземплярах (кожна команда — в окремому вікні, після
`dotnet build SecureLab.sln -c Release`):

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\start-production-instance.ps1 -Port 5080
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\start-production-instance.ps1 -Port 5081
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\redis-search-demo.ps1 -Scenario shared
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\redis-search-demo.ps1 -Scenario outage
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\redis-search-demo.ps1 -Scenario recovery
```

`outage` виконуйте після `docker stop securelab-redis`, `recovery` — після
`docker start securelab-redis` і паузи 12 с. `-NoRedis` у першій команді показує warning
режиму без Redis.

### Повна регресія

Передумови: PostgreSQL Healthy, Redis запущено, пароль seed задано, API зупинено.

```powershell
dotnet restore SecureLab.sln --locked-mode
dotnet build SecureLab.sln -c Release
dotnet run --project src/SecureLab.Api -- --reset-database
dotnet test SecureLab.sln -c Release
dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~RegCsrf01"
```

Очікувано `total: 63; failed: 0` і окремо `Passed: 1` для повного REG-CSRF-01. Тести
REG-REDIS-01/02 потребують живого Redis (`SECURELAB_TEST_REDIS=host:port`, за замовчуванням
`127.0.0.1:6379`). DOM-регресію XSS (`tests/browser/description-dom.js`) запускають у Console
сторінки `browser-lab.html` після входу (`PASS: 31 checks`).

Якщо після копіювання файлів збірка поводиться як стара версія, примусово перезберіть:
`dotnet build SecureLab.sln --no-incremental`.
