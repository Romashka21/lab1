# Модель загроз SecureLab, ЛР 6

Дриг Роман Андрійович, КБ-43. Baseline 2-A «Трекер інцидентів». Рівень: відмінний («Відмінно»).

| Елемент | Що зафіксувати | Ваш запис |
|---|---|---|
| Версія та середовище | commit початку огляду, профіль, seed/reset, SDK | review-start: `⟨REVIEW_START⟩` (гілка `lab/6-hardening-review` від `lab/5-browser-xss` = `v0.5.0` + docs ЛР 5 + `Update SDK policy`); Windows 11, .NET SDK `⟨dotnet --version⟩`, PostgreSQL 18.4 у Docker Compose (`127.0.0.1:54329`); Development (`launchSettings` profile `http`, `http://localhost:5080`) і production-like (`--no-launch-profile`, `ASPNETCORE_ENVIRONMENT=Production`); known state — `dotnet run --project src/SecureLab.Api -- --reset-database`; лише навчальні акаунти seed alice/bob/morgan/admin |
| Компоненти в межах огляду | браузерний клієнт, API, PostgreSQL, конфігурація, журнали | Vanilla JS клієнт (`Client/`: `index.html`/`app.js`, `auth-lab.*`, `browser-lab.*`, `csrf.js`, `styles.css`); ASP.NET Core Minimal API (`Program.cs`, `IncidentEndpoints`, `Lab02Endpoints`, `Lab03Identity`, `Presentation/Security/Antiforgery.cs`); ASP.NET Core Identity + cookie-сеанс; EF Core + Npgsql → PostgreSQL; `appsettings*.json`, `launchSettings.json`, `infra/compose.yaml`, `infra/.env.example`; console log (`ILogger`, категорія `SecureLab.Audit`); NuGet-залежності з `packages.lock.json`; CORS probes `demonstrations/cors-probe` (лише Development). Redis — лише якщо буде погоджено advanced variant |
| Активи | облікові дані, власні записи, привілейовані переходи, аудит, секрети | паролі користувачів (зберігається лише PBKDF2-hash Identity); auth-cookie `.AspNetCore.Identity.Application`; antiforgery-пара (cookie `SecureLab.Antiforgery` + request token); право Reporter змінювати/видаляти лише власні інциденти; конфіденційність чужих інцидентів (політика 404, A-10) і internal comments; privileged transition `Incident.Status` New→Triaged (лише Analyst); audit trail (`incident_status_history`, події `SecureLab.Audit`); connection string і `SeedUsers:Password` (поза Git) |
| Суб’єкти | anonymous, authenticated, moderator/admin, developer | анонімний відвідувач; Reporter (alice, bob); Analyst (morgan); Administrator (admin — без неявних прав, A-07); локальний розробник (reset, конфігурація, restore); стороння сторінка в тому самому браузері (CSRF-контекст, напр. `http://localhost:4174`) |
| Entry points | HTTP-маршрути, login, форми, конфігурація, restore, журнали | `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/me`, `GET /api/auth/session-check`, `GET /api/auth/csrf-token`; `GET /api/incidents`, `/{id}`, `/severity-summary`, `/search?q=&sortBy=`; `POST /api/incidents`, `PUT /api/incidents/{id}`, `DELETE /api/incidents/{id}`, `POST /api/incidents/{id}/triage`; `GET /api/incident-comments/{id}`; `GET /health`; статичні сторінки клієнта; `--reset-database`; змінні середовища `ConnectionStrings__SecureLab`, `SeedUsers__Password`, `ASPNETCORE_ENVIRONMENT`; `dotnet restore --locked-mode`; console log |
| Межі довіри | browser→API, API→PostgreSQL, repository→build, environment→configuration | **browser→API**: усе з браузера (body, query, headers, cookie automatically) недовірене; **API→PostgreSQL**: значення лише параметрами EF Core; **repository→build**: tracked files і NuGet packages; **environment→configuration**: профіль і секрети приходять з оточення, не з Git |
| Наявні controls | з посиланням на код / тест / конфігурацію | validation DTO (T-01…T-10, `Lab02Endpoints`); параметризований ILIKE + allowlist `sortBy` (S-02, T-04, T-05); Identity + cookie HttpOnly/SameSite=Lax/Secure поза Dev (A-01…A-07, cookie-flags test); login rate limit (`RateLimit_Login_...`); ресурсна авторизація `IncidentAuthorizationHandler` + `VisibleTo` (A-01…A-12); safe DOM `setPlainText` (REG-XSS-01, `description-dom.js`); CORS лише Dev, exact origin 4173 (REG-CORS-01); CSP enforcement + nosniff + no-referrer + frame-ancestors (ЛР 5); **ЛР 6**: antiforgery (REG-CSRF-01…03), search limiter (REG-RL-02), headers на error path (REG-HDR-01), production-like профіль (REG-ENV-01), owner-scoped duplicate check (REG-F03-01), audit allowed/denied triage |
| Виключення | що не перевірялося й чому | зовнішній penetration test; реальний production host, TLS termination, HSTS (локально лише HTTP-профіль); Git history повністю, stash, інші клони й зовнішній CI (огляд — поточні tracked files + історія конфігураційних файлів); сторонні браузери, крім Microsoft Edge; Scalar UI (лише Development); навантажувальне тестування; анонімний login-CSRF bootstrap (рішення в security-review, SC-06) |

## Схема меж довіри

```
browser client  (untrusted input, auth-cookie надсилається автоматично;
 │               сторонні сторінки того ж браузера, напр. localhost:4174)
 │  HTTP (local development transport, http://localhost:5080)
 ▼
ASP.NET Core API  (security headers → exception handler → routing → CORS(Dev) →
 │                 authentication → authorization → rate limiter → endpoint filter
 │                 antiforgery → validation → resource authorization → audit log)
 │  connection string з оточення / EF Core параметри
 ▼
PostgreSQL 18 у Docker  (127.0.0.1:54329, дані застосунку, incident_status_history)

repository + NuGet (packages.lock.json) ──► dotnet restore --locked-mode / build
environment (ASPNETCORE_ENVIRONMENT, ConnectionStrings__SecureLab,
             SeedUsers__Password) ──► API startup (Development ≠ Production)
```

## Очікувані властивості на межах

| Межа | Очікувана властивість | Конкретний test або перевірка |
|---|---|---|
| browser→API | cookie-authenticated зміна стану без валідного request token відхиляється 400 без зміни ресурсу; з валідною парою — очікувана зміна | REG-CSRF-01 (`Lab06SecurityTests.RegCsrf01_…`), REG-CSRF-02 (увесь периметр), REG-CSRF-03 (токен іншого сеансу) |
| browser→API | текст користувача не виконується як код у клієнті | REG-XSS-01 (`tests/browser/description-dom.js` PASS, ЛР 5) |
| browser→API | Reporter не читає й не змінює чужий інцидент; чужий = неіснуючий (404); дубліката назви не видно через 409 | A-03, A-04, A-10, A-11 (`Lab04AuthorizationTests`), REG-F03-01 |
| browser→API | сторонній origin не читає відповіді API з cookie | REG-CORS-01 (4173 vs 4174, ЛР 5 + повтор ЛР 6) |
| browser→API | зловживання пошуком обмежене per-user quota; 429 узгоджений | REG-RL-02 (`Lab06RateLimitTests`), login limiter `RateLimit_Login_Returns429_…` |
| browser→API | client не одержує stack trace / SQL / connection string; є traceId | REG-HDR-01 (`Lab06SecurityTests.RegHdr01_…`), ручний Production broken (етап 1, п. 5) |
| API→PostgreSQL | параметр пошуку не змінює структуру SQL | S-02 (`S02_ControlInput_…`, `S02_LiteralWildcards_…`), T-04 |
| repository→build | tracked files не містять реальних credentials; restore не змінює lockfile непомітно | `git grep -n -I -i -E 'password\|passwd\|secret\|api.?key\|token\|connectionstring' -- .`; `dotnet restore SecureLab.sln --locked-mode`; `dotnet package list --vulnerable --include-transitive` |
| environment→configuration | у Production не діє Development-конфігурація, reset заборонено, OpenAPI/CORS probe відсутні | REG-ENV-01 (`Lab06SecurityTests.RegEnv01_…`); консоль `Hosting environment: Production`; відмова `--reset-database` у Production |
