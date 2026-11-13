# Security review SecureLab, ЛР 6

Дриг Роман Андрійович, КБ-43. Baseline 2-A «Трекер інцидентів».

Рівень: **відмінний («Відмінно»)**; рівні накопичувальні. Commit початку огляду (review-start): `42b1085ee5bb0a7f8e895cf949609322a240371e` (`Update SDK policy`, гілка `lab/6-hardening-review` від `lab/5-browser-xss`). Хеші прийнятого merge commit і тегу v1.0.0 додає скрипт експорту в PDF. Дата огляду: 11–13.11.2026. SDK: .NET `10.0.401` (`global.json` `10.0.100`, `rollForward: latestFeature`). Профілі: Development (`launchSettings` `http`, `http://localhost:5080`) і production-like (`--no-launch-profile`, `ASPNETCORE_ENVIRONMENT=Production`). Клієнти: Microsoft Edge 157 (DevTools), `curl.exe`, xUnit + `WebApplicationFactory`.

## 1. Executive summary

Перевірено фактичний fixed state SecureLab після ЛР 1–5: межі довіри браузер→API→PostgreSQL, конфігурацію й tracked files, production-like обробку помилок, повний периметр cookie-authenticated мутацій, security headers/CSP, CORS, rate limiting, залежності та журнали. Зафіксовано й виправлено **три власні знахідки**: **F-01 (P1)** — CSRF: сторонній origin того самого site виконував privileged triage від імені Analyst; **F-03 (P2, поза checklist)** — перевірка дубліката назви повертала 409 на назву чужого інциденту й розкривала його існування всупереч політиці 404; **F-02 (P3)** — на unexpected 500 зникали CSP/`nosniff`/`Referrer-Policy`. Додатково реалізовано search rate limiter per user і погоджений advanced variant — спільний між екземплярами лічильник у Redis із перевіреним fail-safe. Фінальний автоматизований прогін перед злиттям: **63/63 PASS** (`dotnet test SecureLab.sln -c Release`, Redis запущено), окремо повний REG-CSRF-01 — PASS; результат прогону на merge commit записано в метаданих PDF. Головні залишкові ризики: login/register без antiforgery (рішення SC-06/SC-07), локальний лічильник під час відмови Redis починається з нуля, HSTS/TLS не перевірялись (локальний HTTP-стенд).

## 2. Scope та exclusions

**У межах:** поточні tracked files гілки `lab/6-hardening-review` (`git ls-files`), API `src/SecureLab.Api` (endpoints, middleware, конфігурація `appsettings*.json`, `launchSettings.json`), клієнт `Client/`, тести `tests/`, `infra/compose.yaml`, `infra/.env.example`, NuGet lockfiles, console log API, Redis-контейнер `securelab-redis` (`127.0.0.1:6379`).

**Історія Git:** переглянуто лише історію конфігураційних файлів `src/SecureLab.Api/appsettings.Development.json` і `infra/compose.yaml` (`git log --all --follow --oneline`; єдиний commit `a6f1e1d Initial starter code`). Решта історії, stash, інші клони — **не перевірено**.

**Виключення:** зовнішній penetration test; реальний production host, TLS-термінація, HSTS; браузери, крім Edge; навантажувальне тестування; Scalar UI (лише Development); Redis AUTH/TLS і кластер (навчальний контейнер лише на loopback); login-CSRF (див. SC-06/SC-07).

## 3. System overview і trust boundaries

Компоненти, активи, суб'єкти, entry points і схема меж — `docs/threat-model.md`. Кожна межа пов'язана з конкретним тестом (таблиця «Очікувані властивості на межах» там само).

### Asset → threat → control → verification

| Актив | Загроза | Control (код/конфігурація) | Перевірка |
|---|---|---|---|
| Привілейований перехід New→Triaged | CSRF зі стороннього origin того самого site (F-01) | `AntiforgeryValidationFilter` + `RequireAntiforgeryToken()` на triage; токен лише з `GET /api/auth/csrf-token` | REG-CSRF-01…03; ручні S21–S22 → S28–S29 |
| Привілейований перехід | Reporter виконує triage | `IncidentAuthorizationHandler` (Analyst), audit `authorization.denied/allowed` | A-06, A-07; журнал S42 |
| Конфіденційність чужих інцидентів | IDOR / розкриття існування (F-03) | `VisibleTo`, політика 404 (A-10); owner-scoped T-03 | A-03, A-04, A-10, A-11, REG-F03-01; S37–S40 |
| Цілісність власних інцидентів | Overposting, підміна власника, CSRF | DTO без server-managed полів, власник із principal, antiforgery | A-02, A-04/A-05 (ЛР 3), A-08b, REG-CSRF-02 |
| Облікові дані | Brute force / перебір акаунтів | login limiter 20/60 per IP, однакова відповідь 401/429 | `RateLimit_Login_Returns429_ThenRecovers_AndDoesNotRevealAccounts` (S31) |
| Сеанс (auth-cookie) | Крадіжка через XSS, витік у журнали | `HttpOnly`, `SameSite=Lax`, `Secure` поза Dev; safe DOM; CSP | `Cookie_Flags_…`, REG-XSS-01 (S26); лічильники журналу S41 |
| Клієнт у браузері | XSS, MIME sniffing, clickjacking, також на error path (F-02) | CSP `default-src 'self'… frame-ancestors 'none'`, `nosniff`, `no-referrer` через `OnStarting` перед `UseExceptionHandler` | S12–S16, REG-HDR-01 |
| Відповіді API з cookie | Читання стороннім origin | CORS лише Development, exact origin 4173 | REG-CORS-01 (S18–S19) |
| БД | SQL injection | EF Core параметри, ILIKE з ESCAPE, allowlist `sortBy` | S-02, T-04, T-05 |
| Доступність пошуку | Зловживання пошуком, обхід квоти через кілька екземплярів | policy `search` per user; Redis-лічильник; local fail-safe | REG-RL-02, REG-REDIS-01…03; S33–S35, R06–R11 |
| Внутрішня діагностика | Витік stack trace / SQL / connection string | Problem Details + traceId; Production без OpenAPI/CORS/reset | REG-HDR-01, REG-ENV-01; S06–S10 |
| Секрети конфігурації | Реальний секрет у Git | лише відкриті навчальні значення для `127.0.0.1`; реальні — з оточення | secret grep (L04), S05 |

## 4. Methodology та test environment

- **Відомий початковий стан:** `docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait` (PostgreSQL `postgres:18.4-alpine3.24`, `127.0.0.1:54329`, БД `securelab`), `dotnet run --project src/SecureLab.Api -- --reset-database` перед кожним свідомим повтором сценарію й перед тестами. Seed: alice, bob (Reporter), morgan (Analyst), admin; пароль seed — лише змінна `SeedUsers__Password` у вікні PowerShell (`Read-Host -AsSecureString`), не друкувався.
- **Хеші:** початок `42b1085`; виправлення `3e1fdd8` (F-02), `b12d763` (F-01), `ed0d876` (search limiter), `8b36e73` (F-03), `dc00377` (Redis advanced); кінець — merge commit і тег `v1.0.0` (метадані PDF).
- **Профілі:** Development — `dotnet run --project src/SecureLab.Api`; production-like — `..\lr06-resources\commands\Production.ps1 -Mode normal|broken` (broken = БД на закритому порту 54399), для Redis — `scripts\start-production-instance.ps1 -Port 5080|5081 [-NoRedis]` (quota демонстрації 5/30 с).
- **Клієнти й сеанси:** Edge 157, звичайне вікно (alice/morgan) і InPrivate (bob); CORS/CSRF probes `py -3 -m http.server 4173|4174 --directory demonstrations/cors-probe`; `curl.exe`; `scripts\redis-search-demo.ps1` (окремий вхід на 5080 і 5081, cookie показується лише відбитком SHA-256).
- **Команди й коди завершення:** `dotnet restore SecureLab.sln --locked-mode` → 0; `dotnet build SecureLab.sln -c Release` → 0 (TreatWarningsAsErrors); `dotnet package list --vulnerable --include-transitive` → 0; `dotnet test SecureLab.sln -c Release` → 0 (63/63).
- **Спостереження під час роботи:** після `Copy-Item` файли зберігали старий час зміни, і інкрементальний `dotnet build` не перекомпілював їх; через це перший ручний retest F-02 і перший прогін search limiter показали поведінку старої DLL. Причину встановлено, файли «оновлено» (`LastWriteTime`), виконано `dotnet build --no-incremental`, а F-02 і search limiter перевірено повторно (S16, S33–S35, тести 63/63).

## 5. Findings summary

| ID | Актив | Вплив | Ймовірність | Пріоритет | Статус | Retest |
|---|---|---|---|---|---|---|
| F-01 | Привілейований triage, цілісність інцидентів | Високий: зміна стану від імені жертви | Середня: сторінка того самого site + активний сеанс | **P1** | Fixed `b12d763` | REG-CSRF-01…03, S27–S30 |
| F-03 | Конфіденційність чужих інцидентів | Середній: розкриття існування й назви | Висока: будь-який Reporter, звичайна форма | **P2** | Fixed `8b36e73` | REG-F03-01, S40 |
| F-02 | Браузерні політики на error path | Низький: поточне тіло 500 — JSON без даних | Низька: потрібен unexpected error | **P3** | Fixed `3e1fdd8` | REG-HDR-01, S16 |

**Обґрунтування пріоритетів:** F-01 — єдина знахідка, що дозволяла **змінювати** стан, у тому числі привілейований, без участі жертви, тому P1 і виправлена першою після F-02 (F-02 виправлено раніше лише через порядок етапів методики). F-03 — лише розкриття факту існування, але відтворюється будь-яким Reporter без особливих умов, тому P2. F-02 — захисна прогалина без поточного шляху експлуатації, P3.

## 6. Detailed findings

- `docs/findings/F-01-csrf-cookie-mutations.md` — CSRF на cookie-authenticated мутаціях (з checklist).
- `docs/findings/F-02-headers-error-path.md` — security headers на unexpected 500 (з checklist етапу 2, п. 1; не зараховується як третя «поза checklist»).
- `docs/findings/F-03-duplicate-title-oracle.md` — 409-оракул існування чужого інциденту (**поза checklist**, власний аналіз: порівняння read-шляху 404 і write-шляху 409).

## 7. Regression results

Команда: `dotnet run --project src/SecureLab.Api -- --reset-database`, потім `dotnet test SecureLab.sln -c Release --logger "console;verbosity=normal"`. Передумови: PostgreSQL Healthy, `SeedUsers__Password` задано, `securelab-redis` запущено. Результат на `dc00377`: `Total tests: 63, Passed: 63` (S43). Повний REG-CSRF-01 окремо: `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~RegCsrf01"` → `Passed: 1` (S44). Прогін на merge commit — метадані PDF.

| ID | Сценарій | Тест / команда | Результат і стан ресурсу |
|---|---|---|---|
| S-02, T-04, T-05 | SQLi: керувальний ввід, wildcards, апостроф, `sortBy` allowlist | `Lab02SecurityTests.S02_*`, `T04_*`, `T05_*`, `SortBy_Severity_*` | PASS; керувальний ввід → порожній список, `O'Brien` → 200 |
| T-01…T-03, T-09, T-10, A-02 | Validation / overposting | `Lab02SecurityTests.T0*`, `T09`, `T10`, `A02_Overposting_*` | PASS; 400 до БД, server-managed поля ігноруються |
| A-01…A-07 (ЛР 3) | Authentication: 401 без redirect, principal, однакова відповідь на невідомого/хибний пароль, logout | `Lab03SecurityTests.A0*`, `Cookie_Flags_*`, `Deepening_*` | PASS; після logout 401 |
| Login RL | Quota 3/4 с → 429 однаковий для існуючого/неіснуючого, відновлення | `RateLimit_Login_Returns429_ThenRecovers_AndDoesNotRevealAccounts` | PASS (S31) |
| A-01…A-12 (ЛР 4) | Authorization / IDOR: чужий = 404, Analyst 403 на зміну чужого, triage лише Analyst, Admin без неявних прав | `Lab04AuthorizationTests.*` | PASS; стан інциденту Bob/Alice незмінний |
| REG-XSS-01 | Опис і коментарі як текст | `tests/browser/description-dom.js` у Console | `PASS: 31 checks` (S26), marker не виконано |
| REG-CSRF-01 | Login → PUT без токена 400 → стан незмінний → невалідний токен 400 → видача токена → PUT 200 → змінений стан | `Lab06SecurityTests.RegCsrf01_*` | PASS (S44) |
| REG-CSRF-02 | POST, PUT, DELETE, triage, logout без токена | `RegCsrf02_*` | 400 на кожен, стан/сеанс незмінні |
| REG-CSRF-03 | Токен іншого сеансу; token route без login | `RegCsrf03_*` | 400; 401 |
| REG-CORS-01 | Exact origin 4173 читає, 4174 — ні | ручний, Edge (S18, S19) | 4173: `200: [...]`; 4174: CORS error |
| REG-RL-02 | Search per user: quota → 429 problem+json + Retry-After, Bob окремо, маршрут без policy не обмежено, відновлення | `Lab06RateLimitTests.RegRl02_*`; ручний S33–S35 | PASS; вручну 20×200 → 429, `Retry-After: 60`, Bob 200, через 60 с 200 |
| REG-REDIS-01 | Два host, окремі входи Alice, 3+2 → 429 на обох, Bob окремо, у Redis лише число + TTL | `Lab06RedisRateLimitTests.RegRedis01_*` | PASS |
| REG-REDIS-02 | Вікно від першого запиту, відновлення після TTL | `RegRedis02_*` | PASS |
| REG-REDIS-03 | Redis недоступний: не 500, local quota → 429, одна спроба за паузу, один warning без адреси | `RegRedis03_*` | PASS |
| REG-F03-01 | Назва чужого → 201, власний дублікат → 409, PUT → 200 | `Lab06DuplicateTitleTests.RegF03_*` | PASS; інцидент Bob незмінний |
| REG-HDR-01 | 500 у Production: безпечний Problem Details + headers | `Lab06SecurityTests.RegHdr01_*` | PASS |
| REG-ENV-01 | Production: 4xx збережено, OpenAPI 404, профілі різняться | `Lab06SecurityTests.RegEnv01_*` | PASS |

## 8. Hardening controls

### Периметр state-changing маршрутів

Джерела: `git grep` серверних `Map(Post|Put|Patch|Delete)` (L07), клієнтських `method: POST…` (L08), `MapGroup/apiFetch` (L09) — S20. PATCH-маршрутів немає; розбіжностей між сервером і клієнтом не виявлено.

| ID | Method + route | Джерело / розбіжність | Яка зміна стану | Cookie authentication | Browser-accessible | Antiforgery validation | Regression ID |
|---|---|---|---|---|---|---|---|
| SC-01 | `POST /api/incidents` | ЛР 2 (`Lab02Endpoints.cs`), client `auth-lab.js`, `browser-lab.js` | створення інциденту | так | так | explicit | REG-CSRF-02 |
| SC-02 | `PUT /api/incidents/{id}` | ЛР 4 (`IncidentEndpoints.cs`) | зміна назви/опису | так | так | explicit | REG-CSRF-01 |
| SC-03 | `DELETE /api/incidents/{id}` | ЛР 4 (`IncidentEndpoints.cs`) | видалення | так | так | explicit | REG-CSRF-02 |
| SC-04 | `POST /api/incidents/{id}/triage` | ЛР 4 (`IncidentEndpoints.cs`) | New→Triaged (привілейований) | так | так | explicit | REG-CSRF-02, F-01 S28–S29 |
| SC-05 | `POST /api/auth/logout` | ЛР 3 (`Lab03Identity.cs`), client `auth-lab.js` | завершення сеансу | так | так | explicit (до `SignOutAsync`) | REG-CSRF-02 |
| SC-06 | `POST /api/auth/login` | ЛР 3 (`Lab03Identity.cs`) | видача auth-cookie | ні | так | absent — рішення | `RateLimit_Login_*` |
| SC-07 | `POST /api/auth/register` | ЛР 3 (`Lab03Identity.cs`) | створення акаунта Reporter | ні | так | absent — рішення | T-01, T-02 (ЛР 3) |
| SC-08 | `GET /api/auth/csrf-token` | ЛР 6 (`Antiforgery.cs`) | видача antiforgery-пари (не змінює ресурси) | так (`RequireAuthorization`) | так | — (GET, сам видає токен) | REG-CSRF-03 |

**Рішення SC-06/SC-07:** login і register не довіряють наявній auth-cookie, тому класичний CSRF «від імені жертви» до них не застосовний. Залишається login-CSRF (вхід жертви в акаунт атакувальника) — прийнятий ризик навчального стенда: обмежений login limiter, а помилковий сеанс видно в профілі. Контракт: header `X-SecureLab-CSRF`, cookie `SecureLab.Antiforgery` (`HttpOnly`, `SameSite=Strict`, `Secure` поза Development), відмова — `400` Problem Details `Antiforgery token відсутній або недійсний.` без `errors` (відрізняється від validation 400).

### Інші controls

| Control | Ризик | Фактична перевірка (профіль, клієнт, status) | Межа |
|---|---|---|---|
| CSP `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` | XSS, sniffing, clickjacking, витік URL | Production `curl.exe`: `/` 200, OpenAPI 404 (S07); Development Edge: документ 200, `app.js` 200, validation 400, 404 (S12–S15); Production broken 500 (S16). Клієнт не зламано: DOM-тест PASS (S26), сторінки працюють | browser→API |
| CORS лише Development, exact origin `http://localhost:4173`, credentials | Читання відповідей стороннім origin | Edge: 4173 → 200, 4174 → CORS error (S18–S19); у Production policy не реєструється | browser→API |
| Login limiter 20/60 с per IP (ЛР 3) | Brute force | тест 3/4 с → 429 однаковий, відновлення (S31) | browser→API |
| Search limiter 20/60 с per user id (`user:<NameIdentifier>`) | Зловживання пошуком | Edge, Development: Alice 20×200 → 429 + `Retry-After: 60` + Problem Details (S33); Bob (InPrivate) 200 (S34); Alice через 60 с 200 (S35) | browser→API |
| Development vs Production | Dev-налаштування в Production | Production: `Hosting environment: Production` (S06), OpenAPI 404 (S07), reset відмовлено (S08), CORS probe і Scalar відсутні; Development: health + профіль Alice (S11) | environment→configuration |
| Audit trail privileged transition | Невідстежуваний triage | `authorization.denied … result=denied` (Alice) і `authorization.allowed … result=succeeded` (Morgan) з subject/action/resource/time/traceId (S42) | API→log |

### Advanced variant: Redis (погоджено викладачем до реалізації)

Погодження з текстом умов збережено в `docs/evidence/lab06-redis-approval.md`. Відповідність умовам:

| Умова викладача | Рішення | Перевірка |
|---|---|---|
| 1. Номер вікна не з годинника екземпляра | Lua: `INCR`, і лише для значення 1 — `PEXPIRE`; вікно від першого запиту partition; ключ без часу | REG-REDIS-02; R07 (`TTL` 21 → 13 за 5 с) |
| 2. Не лише Development | Вмикається ключем `RateLimit:Search:Redis:ConnectionString` у будь-якому профілі; без ключа — warning на старті | R04 (Production, `-NoRedis` → warn), R05 (обидва Production з Redis → info) |
| 3. Fail-safe: без 500, пауза, один warning, відновлення | Помилка Redis → пауза 10 с без звернень, local `FixedWindowRateLimiter` тієї ж quota; один warning на відмову без адреси; info при відновленні | REG-REDIS-03; R08 (5×200 → 429, 1–5 мс після першого запиту), R09 (один warn), R10–R11 (info «з'єднання відновлено», лічильник знову спільний) |
| 4. Тест із живим Redis і тест fallback | `RegRedis01`, `RegRedis02` (живий), `RegRedis03` (недосяжний порт 6390) | R03 (3/3 PASS), 63/63 |
| 5. Та сама quota й формат 429 | Limiter вбудовано у наявну policy `search` → той самий `OnRejected` (Problem Details + `Retry-After`) | R06 (`429 Retry-After=30`) |
| 6. Окремий вхід на 5080 і 5081 | `redis-search-demo.ps1` логіниться на кожному порту окремо (різні відбитки cookie) | R06: `cookie#c3d9ba80` / `cookie#e5d48e9d`, Alice 3+2 → 429 на обох, Bob 200 |

У Redis зберігається лише `securelab:rl:search:user:<id>` = число (тип `string`) з TTL (R07: `GET` → 7, `TYPE` → string); паролів, cookie й даних інцидентів немає. Порт — лише `127.0.0.1:6379`.

## 9. Dependency and secret audit

**Залежності** (`dotnet restore --locked-mode` → 0; `dotnet package list --vulnerable --include-transitive` → «no vulnerable packages» для обох проєктів, 13.11.2026 01:03, джерело nuget.org (S36, L11/L12); повторно після додавання Redis — те саме (L16)).

| Пакет | Версія | Роль | Рішення |
|---|---|---|---|
| Microsoft.AspNetCore.Identity.EntityFrameworkCore, Microsoft.EntityFrameworkCore(.Relational/.Design), Microsoft.AspNetCore.OpenApi, Microsoft.AspNetCore.Mvc.Testing | 10.0.10 | платформа, Identity, EF Core, тести | залишити; узгоджено з SDK 10, advisory немає |
| Microsoft.OpenApi | 2.7.5 | прямо й транзитивно через AspNetCore.OpenApi (`dotnet nuget why`, L13) | пряме посилання фіксує версію; OpenAPI доступний лише в Development |
| Npgsql.EntityFrameworkCore.PostgreSQL | 10.0.3 | провайдер PostgreSQL | залишити |
| Scalar.AspNetCore | 2.16.16 | API reference | лише Development (у Production маршрут не мапиться) |
| StackExchange.Redis (+ Pipelines.Sockets.Unofficial 2.2.8) | 2.8.16 | advanced variant | додано з фіксованою версією, lockfiles оновлено (`--force-evaluate`), advisory немає |
| xunit 2.9.3, xunit.runner.visualstudio 3.1.4, Microsoft.NET.Test.Sdk 17.14.1, coverlet.collector 6.0.4 | — | лише тести | не потрапляють у збірку API |

**Секрети:** `git ls-files '*appsettings*.json' '*.env*' '*compose*.yml' '*compose*.yaml' '*.config'` (S05, L01); `git check-ignore -v infra/.env appsettings.Local.json` → обидва ігноруються (`exit=0`); `git grep -n -I -i -E 'password|passwd|secret|api.?key|token|connectionstring' -- .` → 193 рядки (L04). Класифікація:

| Збіг | Класифікація |
|---|---|
| `local-study-password` у `appsettings.Development.json`, `infra/compose.yaml`, `SecureLabDesignTimeDbContextFactory.cs`, `scripts/start-production-instance.ps1`, README | відкриті навчальні credentials лише для БД на `127.0.0.1`, задокументовані README (повторне використання заборонено) — **accepted, study-only** |
| `SeedUsers__Password` / `SeedUsers:Password` у коді, тестах, `tests/http/*.py` | лише ім'я змінної; значення приходить з оточення, у Git його немає |
| `Password`, `PasswordHash`, `SecurityStamp`, `ConcurrencyStamp`, `token`, `CancellationToken`, `UserSecrets` у коді, міграціях, lockfiles | ідентифікатори, не значення |
| Згадки в `docs/*.md`, `.gitignore` | опис правил, не значення |

Якби навчальний пароль був реальним секретом, видалення з поточного файла не допомогло б: значення лишається в історії Git, клонах і форках. Потрібна rotation (зміна пароля БД), після — очищення історії й примусове оновлення клонів за процедурою власника репозиторію.

**Журнали:** 6 сценаріїв (успішний вхід, невдалий вхід, 403 triage, 400 validation, 200 privileged transition, unexpected 500) записано в `..\lr06-logs\api.log` (поза Git). Лічильники входжень: seed password 0, `NotARealPassword1!` 0, `cookie:`/`set-cookie` 0, `.AspNetCore.Identity.Application` 0, `X-SecureLab-CSRF` 0, `SecureLab.Antiforgery` 0, `local-study-password` 0 (S41).

## 10. Residual risks

| Ризик | Статус | Відповідальний | Наступна дія |
|---|---|---|---|
| Login-CSRF (SC-06/SC-07 без antiforgery) | тимчасово прийнято | автор | за потреби — anonymous antiforgery bootstrap для форм входу |
| Під час відмови Redis кожен екземпляр рахує окремо, лічильник починається з нуля (до N×quota за вікно) | прийнято (погоджений fail-safe) | автор | моніторинг warning; для критичних квот — fail-closed або Redis HA |
| Redis без AUTH/TLS | прийнято для loopback-стенда | автор | `requirepass`/ACL і TLS у реальному середовищі |
| HSTS, TLS, `Secure`-cookie на реальному HTTPS не перевірено | не перевірено | автор | перевірка на стенді з TLS-термінацією |
| XSS у власному origin обійшов би antiforgery | знижено CSP і safe DOM | автор | зберігати REG-XSS-01 у регресії |
| Історія Git (крім двох конфігураційних файлів) не скановано | не перевірено | автор | `gitleaks`/аналог на всій історії перед публікацією |

## 11. Conclusion

Три власні знахідки (P1 CSRF, P2 оракул існування, P3 headers на error path) відтворено, виправлено й повторно перевірено вручну та автоматичними тестами; позитивні регресії клієнта (створення, logout, DOM-тест ЛР 5) працюють. Search limiter і погоджений Redis-варіант показали спільну квоту між двома production-like екземплярами, ізоляцію partitions, TTL і безпечну деградацію без 500. Фінальний автоматизований прогін перед злиттям — 63/63 PASS; тег `v1.0.0` ставиться лише на merge commit після повторного прогону.

## 12. Evidence appendix

**Доказ відсутності чутливих даних у журналах (етап 3, п. 4).** API запущено як `dotnet run --project src/SecureLab.Api 2>&1 | Tee-Object -FilePath ..\lr06-logs\api.log`, потім `Production.ps1 -Mode broken … -Append`. Перевірка — `Select-String -SimpleMatch` по кожному значенню (S41, усі 0). Події (`L14-log-events.txt`, S42):

```
Auth event login: result success, user alice, trace 0HNQ12O2OA3BJ:00000007
Auth event login: result failure, trace 0HNQ12O2OA3BJ:0000000E
authorization.denied subject=10000000-0000-0000-0000-000000000001 action=incident.triage resource=cfe50ce9-6cbb-4434-a1a1-aa6e8023a2c1 result=denied … traceId=00-6867983e9b955f85ebfa897be58d9c30-…
Auth event login: result success, user morgan, trace 0HNQ12O2OA3BL:0000000E
authorization.allowed subject=10000000-0000-0000-0000-000000000003 action=incident.triage resource=cfe50ce9-6cbb-4434-a1a1-aa6e8023a2c1 result=succeeded … traceId=00-b92a37beb4eb458b2a659a154a3eddf8-…
Hosting environment: Production
fail: Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware[1]
```

**Зв'язок відповіді з журналом через traceId.** 500 у сценарії 6: `traceId 00-d6e6978a13f8e56d865bba52464f267f-fb68e636a927d129-00`; у журналі той самий `TraceId:d6e6978a13f8e56d865bba52464f267f`, `SpanId:fb68e636a927d129`, `RequestPath:/api/auth/login`. До F-02: `00-968fac066cc17c4e04ea625e84758d0b-…` ↔ `TraceId:968fac066cc17c4e04ea625e84758d0b` (S09–S10).

**Відтворення для іншої людини.** З кореня SecureLab, PowerShell, `SeedUsers__Password` задано, PostgreSQL Healthy, `docker start securelab-redis`:

```powershell
dotnet restore SecureLab.sln --locked-mode
dotnet build SecureLab.sln -c Release
dotnet run --project src/SecureLab.Api -- --reset-database
dotnet test SecureLab.sln -c Release
dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~RegCsrf01"
```

Ручні retest — кроки в картках `docs/findings/F-0*.md` (розділи «Відтворення», «Retest»); Redis-демонстрація — `scripts\start-production-instance.ps1 -Port 5080` і `-Port 5081` у двох вікнах, потім `scripts\redis-search-demo.ps1 -Scenario shared|outage|recovery` (README, розділ 8).

## Декларація й журнал ШІ

**Використовував.** Сервіс: Claude (Anthropic). Застосовувався як консультант і помічник: пояснення вимог методички, покроковий план виконання (команди PowerShell, які вікна, що фіксувати), чернетки коду виправлень і тестів, діагностика помилок, чернетки текстів review/findings. Код я вносив у власний проєкт сам (VS Code / PowerShell), збирав і запускав тести на своєму комп'ютері; кожне виправлення спершу відтворював «до», потім перевіряв «після» вручну в браузері й тестами. Знахідки, пріоритети й рішення щодо прийнятих ризиків перевірені й сформульовані мною на основі фактичних спостережень. Паролі, cookie й токени в ШІ не передавались.

| Дата | Сервіс | Завдання/фрагмент | Авторська адаптація | Перевірка й результат |
|---|---|---|---|---|
| 11.11.2026 | Claude | План огляду, threat model, команди етапу 1 (secret grep, production-like, reset) | Заповнено фактами свого стенда (хеші, SDK 10.0.401, 193 збіги grep) | S01–S11, L01–L06 |
| 11.11.2026 | Claude | F-02: перенесення headers у `OnStarting` перед `UseExceptionHandler`; тест RegHdr01 | Відтворив 500 без headers до fix; після fix — повторна перевірка | S09–S10 → S16, RegHdr01 PASS |
| 11–12.11.2026 | Claude | F-01: `Antiforgery.cs`, `csrf.js`, filter на маршрутах, тести REG-CSRF-01…03, адаптація тестів ЛР 2–4 | Перевірив периметр grep, відтворив CSRF з 4174 до fix, ручні сценарії після fix | S21–S30, 58/58 |
| 12.11.2026 | Claude | Search limiter per user, узгоджений 429, RegRl02; діагностика інкрементального build | Знайдено причину (старі mtime після Copy-Item), перезбірка `--no-incremental`, повторна перевірка | S33–S35, 59/59 |
| 12.11.2026 | Claude | F-03 (owner-scoped T-03), audit allowed triage, RegF03 | Знахідку відтворено вручну (404 vs 409) до fix | S37–S40, 60/60 |
| 12–13.11.2026 | Claude | Redis advanced: текст погодження, `RedisSearchRateLimiter.cs`, тести REG-REDIS, демо-скрипти | Погодження викладача отримано до реалізації; сценарії shared/outage/recovery виконано на двох екземплярах | R01–R11, 63/63 |
| 13.11.2026 | Claude | Чернетки security-review, findings, README, звіту | Звірено з фактичними скріншотами, логами й хешами | цей документ |
