# F-01. Cookie-authenticated mutations без antiforgery (CSRF)

**Статус:** Fixed (`b12d763`)  
**Актив:** привілейований перехід `Incident.Status` New→Triaged, цілісність власних інцидентів, сеанс користувача  
**Компонент:** `POST /api/incidents`, `PUT /api/incidents/{id}`, `DELETE /api/incidents/{id}`, `POST /api/incidents/{id}/triage`, `POST /api/auth/logout`  
**Пріоритет:** P1

## Передумови і межі огляду

- Commit відтворення: `3e1fdd8` (review-start `42b1085` + F-02), гілка `lab/6-hardening-review`.
- Development, `dotnet run --project src/SecureLab.Api`, `http://localhost:5080`; стан після `-- --reset-database`.
- Акаунт жертви: `morgan` (Analyst). Стороння сторінка: CORS probe ЛР 5 на `http://localhost:4174` (той самий site `localhost`, інший origin; у CORS policy не дозволений).
- Клієнт: Microsoft Edge 157, DevTools Console/Network.
- Виключення: зовнішні hosts не використовувались; login/register оцінено окремо (security-review, SC-06/SC-07).

## Відтворення

1. Morgan входить на `http://localhost:5080/auth-lab.html` і створює інцидент `CSRF victim` → `201`, id `70f31723-3bc4-4aca-9b12-9a66bd0994ad`, статус `New` (S21).
2. У тому самому браузері відкрито `http://localhost:4174/`; у Console виконано:
   `fetch("http://localhost:5080/api/incidents/70f31723-…/triage", { method: "POST", credentials: "include" })`.
3. **Expected:** сервер відмовляє, стан не змінюється.
   **Actual:** Network — `POST …/triage` **200 OK**; Console — `blocked by CORS policy` + `net::ERR_FAILED 200`: CORS заблокував лише **читання** відповіді, але не виконання запиту (S21).
4. `GET http://localhost:5080/api/incidents/70f31723-…` → `"status":"Triaged"` (S22): чужа сторінка змінила стан від імені Morgan.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

Будь-яка сторінка того самого site (інший порт `localhost`, піддомен, сторінка з XSS у сусідньому застосунку) може змусити браузер автентифікованого користувача виконати зміну стану: triage від імені Analyst, створення/редагування/видалення власних інцидентів Reporter, logout. Простий `POST` без тіла не потребує CORS preflight, тому CORS не захищає. Cookie `SameSite=Lax` не допомагає в межах одного site. Ймовірність — середня (потрібна сторінка в тому самому site й активний сеанс жертви), вплив — високий (привілейований перехід і цілісність даних), тому P1.

## Першопричина

Автентифікація мутацій спиралася лише на cookie, яку браузер додає автоматично. У Minimal API не було перевірки секрету, який стороння сторінка не може прочитати: `AddAntiforgery`/`IAntiforgery.ValidateRequestAsync` не налаштовано, а клієнт надсилав мутації звичайним `fetch` без request token.

## Виправлення

Коміт `b12d763`:
- `Presentation/Security/Antiforgery.cs` (новий): `AddSecureLabAntiforgery()` — header `X-SecureLab-CSRF`, cookie `SecureLab.Antiforgery` (`HttpOnly`, `SameSite=Strict`, `Secure` поза Development); `MapCsrfToken()` — `GET /api/auth/csrf-token` лише для автентифікованого користувача (`IAntiforgery.GetAndStoreTokens`); endpoint filter `AntiforgeryValidationFilter` (`ValidateRequestAsync`, при відмові — `400` Problem Details «Antiforgery token відсутній або недійсний.» **до** handler) і розширення `RequireAntiforgeryToken()`.
- Filter додано явно до кожного cookie-mutation маршруту: `IncidentEndpoints.cs` (PUT, DELETE, triage), `Lab02Endpoints.cs` (POST create), `Lab03Identity.cs` (logout — перевірка до `SignOutAsync`).
- Клієнт: спільний helper `Client/csrf.js` (`SecureLabCsrf.mutate` бере токен із token route й додає header лише до same-origin POST/PUT/PATCH/DELETE; `reset()` після login/logout і на 400/401); `auth-lab.js`, `browser-lab.js`, `tests/browser/description-dom.js` переведено на нього.
- Тести: `LoginWithCsrfAsync` для легітимних мутацій наявних тестів ЛР 2–4; нові REG-CSRF-01…03.

Це усуває причину: чужа сторінка не може прочитати ні токен (відповідь token route закрита CORS і same-origin), ні `HttpOnly` cookie, а без пари cookie+header сервер відповідає 400 до будь-якої зміни.

## Retest

1. Після fix Morgan створює `CSRF victim 2` → `201`, id `7068556b-350b-46b7-b1d2-707d203e8632` (S28).
2. Той самий `fetch` з `http://localhost:4174` → Network `triage` **400** (S28).
3. `GET /api/incidents/7068556b-…` → `"status":"New"` (S29): стан не змінився.
4. Запит без header у власному origin: `fetch("/api/incidents", {method:"POST", …})` → `400`, title «Antiforgery token відсутній або недійсний.» (S27).
5. Автоматизовано: `RegCsrf01_PutWithoutToken_IsRejected_StateUnchanged_ThenValidPairChangesState` (вхід → відмова без токена → незмінний стан → невалідний токен → видача токена → дозволена зміна → змінений стан), `RegCsrf02_AllCookieMutations_WithoutToken_Return400_AndDoNotChangeState` (POST, PUT, DELETE, triage, logout), `RegCsrf03_TokenFromAnotherSession_IsRejected_AndTokenRouteRequiresLogin` — PASS (S44, фінальний прогін 63/63).

## Positive regression

- `auth-lab.html`: login → створення `CSRF ok 1` → 201; у Network `csrf-token` 200 і `incidents` 201 з header `X-SecureLab-CSRF` (S24, значення приховано).
- `browser-lab.html`: створення `CSRF ok 2` → 201 з власним токеном сторінки (S25).
- DOM-тест ЛР 5 після antiforgery: `PASS: 31 checks` (S26).
- Logout 204 → профіль 401 → новий вхід → створення 201 (S30); тести ЛР 2–4 (валидація, IDOR, triage Analyst) проходять із токеном.

## Залишковий ризик

- Login і register не захищені antiforgery (анонімні; login-CSRF прийнято як рішення SC-06/SC-07 з обґрунтуванням у review).
- Захист залежить від того, що жоден same-origin скрипт не скомпрометований: XSS у власному origin може прочитати токен (контроль — CSP і safe DOM ЛР 5).
- Локально перевірено лише HTTP; прапорець `Secure` для antiforgery cookie діє поза Development і підтверджений конфігурацією, а не TLS-стендом.

## Доказ

S21, S22 (до fix); S24–S30 (після fix); `dotnet test SecureLab.sln -c Release --filter "FullyQualifiedName~RegCsrf01"` → `Passed: 1` (S44). Значення cookie й токенів у звіт не переносились.
