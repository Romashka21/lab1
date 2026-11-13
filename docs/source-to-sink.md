# Карта source-to-sink — ЛР 5

Студент: Дриг Роман Андрійович, КБ-43. Сценарій 2-A, рівень «Відмінно».
Стан: vulnerable — `4bff1ce` (встановлення scaffold `lab-05-start-v1`); seed коментаря — `4353b68`; fixed — `8c66351` (заміна sinks у `browser-lab.js`); CORS/CSP — `e6f10b7` = тег `v0.5.0`.
Докази (DB/API/DOM, до і після) — `docs/browser-security-evidence.md`.

## Потік 1 (для всіх): Incident.Description

Вхід: Alice через `/auth-lab.html`, створення на `/browser-lab.html` (форма «Створити й прочитати»), читання за Guid нового інциденту.

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `Client/browser-lab.html`, `<textarea name="description">` у формі `#edit` | текст, уведений користувачем (marker з `resources/lab05-marker.txt`) | контрольоване користувачем |
| Request | `Client/browser-lab.js`, обробник `submit` форми `#edit` → `fetch("/api/incidents", POST)`; `Scaffolding/Lab02Endpoints.cs`, `CreateIncidentRequest(Title, Description, Severity, OccurredAtUtc)` | JSON field `description` у Network → Payload | контрольоване користувачем |
| Validation/mapping | `Lab02Endpoints.cs`, `MapPost("/api/incidents")`: required, довжина ≤ 4000, `Trim()`, T-09, T-10; owner з principal (ЛР 3) | `incident.Description = description` | validation перевіряє бізнес-формат і довжину; HTML не очищується і не має очищуватись — значення лишається недовіреним |
| Storage | `Data/Entities/Incident.cs` → PostgreSQL `incidents.description` | те саме значення, символ у символ | збережене значення користувача (запис у БД не робить його trusted) |
| Response | `GET /api/incidents/{id}` → `Presentation/Endpoints/IncidentEndpoints.cs` `GetDetailsAsync` (рішення handler ЛР 4) → `Application/Incidents/IncidentQueries.cs` `GetDetailsAsync` → `IncidentDetailsResponse.Description` | JSON field `description` у Network → Response (лапки записано як `\"` — запис JSON, а не зміна) | недовірене для відображення; JSON-escape не захищає HTML sink |
| Client transform | `browser-lab.js`, `load()`: `current = await response.json()` → `current.description` | без перетворень | недовірене |
| Sink/context (vulnerable) | `browser-lab.js`, `load()`: `document.querySelector("#description").innerHTML = current.description` | HTML parser створює `<img src=x onerror=…>` | **небезпечно**: HTML/code context → stored XSS, виконаний через клієнтський DOM sink |
| Sink/context (fixed) | `browser-lab.js`, `setPlainText(#description, current.description)` → `createTextNode` | один текстовий вузол | безпечно: контекст text node, HTML parser значення не бачить |

## Потік 2 («Добре / Відмінно»): IncidentComment.Text

| Крок | Файл та функція/DTO | Конкретне поле/значення | Доказ і довіра |
|---|---|---|---|
| Source | `Data/DbSeeder.cs`, `SeedAsync`, константа `Lab05Marker`, коментар `30000000-0000-0000-0000-000000000005` (автор Morgan, `IsInternal = false`) | marker | у продукті — текст будь-якого автора коментаря; контрольоване користувачем |
| Request | seed під час `--reset-database` (endpoint створення коментаря в API немає) | — | — |
| Storage | `Data/Entities/IncidentComment.cs` → PostgreSQL `incident_comments.text` | те саме значення | збережене значення користувача |
| Response | `IncidentQueries.GetDetailsAsync` → `IncidentCommentResponse.Text` (internal — лише для Analyst, правило ЛР 4) | JSON `comments[].text` | недовірене |
| Client transform | `browser-lab.js`, `load()`: цикл по `current.comments ?? []` | без перетворень | недовірене |
| Sink/context (vulnerable) | `paragraph.innerHTML = comment.text` | `<img>` у `<div id="comments">` | **небезпечно**: HTML/code context |
| Sink/context (fixed) | `setPlainText(document.createElement("p"), comment.text)`; `#comments.replaceChildren(...paragraphs)` | один текстовий вузол у кожному `<p>`; повторний render замінює, а не дописує | безпечно |

## Інвентаризація DOM sinks власного клієнта

| Місце | Дані, що потрапляють у sink | Категорія | Контекст | Рішення |
|---|---|---|---|---|
| `browser-lab.js` `#title.textContent = current.title` | Title | збережене значення користувача | text node | безпечно, без змін |
| `browser-lab.js` `#description.innerHTML` | Description | збережене значення користувача | HTML parser | **виправлено** → `setPlainText` |
| `browser-lab.js` `paragraph.innerHTML = comment.text` | comments[].text | збережене значення користувача | HTML parser | **виправлено** → `setPlainText` |
| `browser-lab.js` `status.textContent = \`GET: ${response.status}\`` | HTTP status | server-generated | text node | безпечно |
| `browser-lab.js` `edit.elements.description.value = …` | Description | збережене значення користувача | значення поля форми (DOM property) | безпечно: `value` не розбирається як HTML |
| `app.js` `createTextElement(...)`, `document.createTextNode(comment.text)`, `li.textContent` | Title, Description, comments, severity summary | збережене значення / server-generated | text node | безпечно (ЛР 1), без змін |
| `auth-lab.js` | профіль, результати запитів | server-generated / значення користувача | `textContent` | безпечно (ЛР 3) |
| `demonstrations/cors-probe/probe.js` `output.textContent` | HTTP response | дані API | text node | безпечно |
| `browser-lab.html`, `index.html`, `auth-lab.html` | статичний markup | trusted constant | HTML | допустимо: user data не конкатенується |
| URL/атрибути з даних | — | — | — | у клієнті немає `href`/`src` з даних; для майбутніх посилань — правило `safeHttpUrl` (див. evidence, Відмінно) |
| Сторонній код | Scalar UI на `/scalar` (лише Development) | third-party | — | не бере участі в досліджуваному flow; виняток CSP описано як залишковий ризик |

Поглиблена перевірка comments і повторного render («Відмінно»): DOM-тест `tests/browser/description-dom.js` перевіряє кожен `comments[].text` seed-інциденту Alice, відсутність HTML-елементів у кожному `<p>` і що повторний `load()` не дублює `<p>` і лишає один текстовий вузол в `#description`. Результати — у `docs/browser-security-evidence.md`.
