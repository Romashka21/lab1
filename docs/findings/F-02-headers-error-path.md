# F-02. Security headers відсутні на unexpected 500

**Статус:** Fixed (`3e1fdd8`)  
**Актив:** захист клієнта браузерними політиками (CSP, `nosniff`, `Referrer-Policy`) на всіх відповідях  
**Компонент:** конвеєр middleware у `src/SecureLab.Api/Program.cs` (headers ЛР 5 + `UseExceptionHandler`)  
**Пріоритет:** P3

## Передумови і межі огляду

- Commit відтворення: `42b1085` (review-start), production-like профіль через `..\lr06-resources\commands\Production.ps1 -Mode broken` (Production, БД на закритому порту `54399` → контрольований 500).
- Клієнт: `curl.exe` (Windows), тіло login з файла `..\lr06-logs\login-body.json` (навмисно хибний пароль `NotARealPassword1!`, реальний пароль не використовувався).
- Методика прямо називає error-path gap заголовків (етап 2, п. 1), тому F-02 **не** зараховано як третю знахідку «поза checklist».

## Відтворення

1. Вікно 1: `powershell -NoProfile -ExecutionPolicy Bypass -File ..\lr06-resources\commands\Production.ps1 -Mode broken`.
2. Вікно 2: `curl.exe -sS -i -X POST http://localhost:5080/api/auth/login -H "Content-Type: application/json" -H "Accept: application/problem+json" --data-binary "@..\lr06-logs\login-body.json"`.
3. **Expected:** безпечний Problem Details 500 **з** тими самими headers, що й на 200.
   **Actual:** `HTTP/1.1 500`, `Content-Type: application/problem+json`, `traceId 00-968fac066cc17c4e04ea625e84758d0b-…`, але **немає** `X-Content-Type-Options`, `Referrer-Policy`, `Content-Security-Policy`. Контроль: `curl.exe -sS -D - -o NUL http://localhost:5080/` у тому самому екземплярі — 200 **з** усіма трьома headers (S09).
4. У журналі API `fail: Microsoft.AspNetCore.Diagnostics.ExceptionHandlerMiddleware[1]` з тим самим `TraceId:968fac066cc17c4e04ea625e84758d0b` (S10): зв'язок відповіді й внутрішньої діагностики є, внутрішні деталі клієнту не віддано.

## Вплив і ймовірність

**Статус перевірки:** спостережено локально.

На error path браузер не одержує CSP і `nosniff`. Поточне тіло 500 — JSON без даних користувача, тому прямої експлуатації немає; але будь-яка майбутня error-сторінка (HTML, відображення частини запиту) лишилася б без CSP, а `Referrer-Policy` не діяла б для переходів з неї. Вплив низький, ймовірність низька → P3.

## Першопричина

Middleware ЛР 5 ставив headers **після** `UseExceptionHandler()` і записував їх напряму в `Response.Headers` до виклику `next`. Коли далі в конвеєрі виникає виняток, `ExceptionHandlerMiddleware` очищає відповідь (`Response.Clear()`, разом із headers) і пише Problem Details заново — headers, установлені раніше, втрачаються.

## Виправлення

Коміт `3e1fdd8`, `Program.cs` (фінальний стан — рядки 156–189): middleware перенесено **перед** `app.UseExceptionHandler(); app.UseStatusCodePages();`, а headers ставляться в `context.Response.OnStarting(...)`. Callback виконується безпосередньо перед надсиланням headers будь-якої відповіді, у тому числі вже після очищення exception handler'ом. Виняток для Development-шляху `/scalar` збережено.

## Retest

1. Той самий сценарій `Production.ps1 -Mode broken` + `curl.exe … /api/auth/login` після fix → `HTTP/1.1 500`, `application/problem+json`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, повна `Content-Security-Policy`, `traceId 00-efe676f0f59dee12751a6fa21cd991bf-…` (S16).
2. Автоматизовано: `RegHdr01_UnexpectedError_InProduction_IsSafeProblem_WithSecurityHeaders` (Production host, БД `127.0.0.1:54399`): 500, problem+json, є `traceId`, немає stack trace/SQL/connection string, усі три headers — PASS.

## Positive regression

- `GET /` → 200 з тими самими headers (S09, S12); `app.js`, 400 validation і 404 також з headers (S13–S15).
- Сторінки клієнта (auth-lab, browser-lab) працюють під CSP; DOM-тест ЛР 5 `PASS: 31 checks` (S26).

## Залишковий ризик

HSTS не налаштовано (локально HTTP; HSTS має ставити TLS-термінація реального середовища). Headers на відповідях, які сформує сам Kestrel до конвеєра (наприклад, 400 на некоректний HTTP-запит), не перевірялись.

## Доказ

S09, S10 (до fix), S16 (після fix), `RegHdr01_…` у фінальному прогоні 63/63; журнал `..\lr06-logs\L05-production-broken-before.log` / `L06-production-broken-after.log` (поза Git).
