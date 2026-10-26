# Звіт ЛР04 — авторизація, ролі, володіння ресурсом та IDOR/BOLA

Студент: Дриг Роман Андрійович, група КБ-43. Варіант: baseline 2-A «Трекер інцидентів».

## Контекст і межа виконання
- **Рівень:** відмінний («Відмінно»). Виконано весь достатній і добрий рівень, а також A-11 (search і severity-summary), відокремлений resource-based handler і обґрунтування least privilege, видимості та залишкового ризику.
- **Власний baseline 2-A, base tag і hash:** `v0.3.0` → `b03a402834f2e58e1e6e91a88bf250c4797f75a8`. Гілка `lab/4-authorization` створена від цього тегу.
- **Головна action:** details/read `GET /api/incidents/{id}`. На доброму й відмінному рівні додатково охоплено list, update, delete, triage, child endpoint коментарів, search і severity-summary.
- **Політика відмов:** анонім → `401`. Ресурс, який principal не має права бачити, → `404`, так само як неіснуючий. Видимий ресурс без права на дію → `403`.
- **Маршрути мого рівня:** `GET /api/incidents`, `GET /api/incidents/{id}`, `POST /api/incidents` (baseline ЛР 3), `PUT /api/incidents/{id}`, `DELETE /api/incidents/{id}`, `POST /api/incidents/{id}/triage`, `GET /api/incident-comments/{id}`, `GET /api/incidents/search`, `GET /api/incidents/severity-summary`.
- **ЛР 3 після тегу не виправлялась.** Тег `v0.3.0` не пересувався.

| Commit | Hash | Зміст |
|---|---|---|
| base (тег v0.3.0) | `b03a402834f2e58e1e6e91a88bf250c4797f75a8` | стан після ЛР 3 |
| seed | `f595a0a` | internal comment `30000000-0000-0000-0000-000000000003` (IsInternal = true) до інциденту Alice |
| **vulnerable** | `cdf6e751922e28f77ba0c5be1c528e969329ec7f` | mutation/child endpoint-и без ресурсного рішення, сценарій PoC, матриця, початок звіту |
| **fixed (тег v0.4.0)** | `e0f248873297aca1ad520ef9a46280ed91eb9621` | handler, query scoping, DTO-контракт, audit, тести A-01…A-12 |

## Матриця і server-side рішення
Повна матриця — `docs/access-matrix.md`. Конкретні правила:

| Операція | Reporter | Analyst | Administrator |
|---|---|---|---|
| Read (details, list, search, summary) | лише власні; чужі → 404 | усі інциденти (для аналізу) | лише власні (немає → `[]` / 404) |
| Update content (title, description) | власник, якщо статус ≠ Closed; інакше 403 | 403 | 404 |
| Delete | власник, лише у статусі New; інакше 403 | 403 | 404 |
| Triage New → Triaged | 403 (власник) / 404 (чужий) + audit | allow; поточний статус ≠ New → 409 | 404 + audit |
| Коментар за прямим id | лише до видимого parent і не internal; інакше 404 | allow | 404 |
| Internal comment | ніколи (ані endpoint, ані details-проєкція) | allow після доступу до parent | ніколи |

Де це реалізовано:
- **Єдине місце правил:** `src/SecureLab.Api/Application/Incidents/IncidentAccess.cs`. Там лежать:
  - `IncidentOperations`: Read, ReadInternalComments, Update, Delete, Triage;
  - `IncidentAuthorizationHandler : AuthorizationHandler<OperationAuthorizationRequirement, Incident>`;
  - `IncidentViewer.FromPrincipal`: id береться з `ClaimTypes.NameIdentifier`, роль — через `IsInRole(DbSeeder.AnalystRole)`;
  - `IncidentVisibility.VisibleTo`: те саме правило Read як query scoping.
- **Реєстрація:** `Program.cs` → `AddSingleton<IAuthorizationHandler, IncidentAuthorizationHandler>()`.
- **Query scoping:** `IncidentQueries.GetListAsync`, `IncidentQueries.GetSeveritySummaryAsync` (фільтр до `GroupBy`) і пошук у `Lab02Endpoints.cs` (фільтр до сортування й `Take(50)`).
- **Resource-based рішення:** `IncidentEndpoints.cs` → `GetDetailsAsync`, `UpdateAsync`, `DeleteAsync`, `TriageAsync`, `GetCommentAsync`. Endpoint завантажує entity і викликає `IAuthorizationService.AuthorizeAsync`. Response DTO формується лише після дозволу. `OwnerUserId` у DTO не потрапляє.
- **Захист маршрутів:** група `/api/incidents` → `.RequireAuthorization()`. Окремо захищено `/api/incident-comments/{id}` і `/api/incidents/search`.
- **Дозволені DTO:** `UpdateIncidentRequest(Title, Description)` і `TriageIncidentRequest(Note)` з `[JsonUnmappedMemberHandling(Disallow)]`. Owner, status, role, id у контракті відсутні; будь-яке зайве поле → `400`.
- **Server-managed fields:** `OwnerUserId` (principal при створенні), `Status` (лише triage, наступний статус ставить сервер), `Id`, `CreatedAtUtc`, `UpdatedAtUtc`, записи `IncidentStatusHistory`.

## Вразливий стан і PoC
Vulnerable commit: `cdf6e751922e28f77ba0c5be1c528e969329ec7f`.

У ньому `GetDetailsAsync` (стан після ЛР 3) шукає інцидент лише за id. Додані `PUT`, `DELETE`, `POST …/triage` і `GET /api/incident-comments/{id}` вимагають лише login, ресурсного рішення в них немає. Звичайний update приймав ще й `Status`.

Відтворення: `py -3 ../lr04-resources/commands/login-and-read.py` і повторюваний сценарій `tests/http/lab04_scenarios.py`. Cookie живе лише в пам'яті процесу, пароль береться зі змінної `SeedUsers__Password` і не друкується.

| Суб'єкт → ресурс | Дія | Очікувано за матрицею | Фактично (vulnerable) |
|---|---|---|---|
| Alice → свій інцидент …0001 | GET details | 200 | 200, «Підозрілий лист із вкладенням» |
| Alice → інцидент Bob …0002 | GET details | 404 | **200**: `{"id": "…0002", "title": "Невідома спроба входу", "ownerDisplayName": "Боб Мельник"}` |
| анонім → …0001 | GET details | 401 | **200**, повні details |
| Alice → невідомий id | GET details | 404 | 404 з detail «Інцидент '<id>' не існує.» (відрізнявся від чужого) |
| Alice → інцидент Bob | PUT title/description | 404, стан без змін | **200**, у Bob title став «Змінено Alice (PoC)» |
| Alice → інцидент, створений Bob | DELETE | 404 | **204**, Bob далі отримує 404: інцидент видалено |
| Alice (Reporter) → власний New | POST triage | 403 | **200**, статус `Triaged` |
| Alice → власний New | PUT із `"status": "Closed"` | 400 | **200**, статус `Closed` (overposting) |
| Alice → коментар Morgan до інциденту Bob | GET comment-2 | 404 | **200**, текст коментаря |
| Alice → internal comment до свого інциденту | GET comment-3 | 404 | **200**, текст internal comment |
| Alice → search `q=O'Brien` | GET | `[]` | **[інцидент Bob …0004]** |
| Alice → severity-summary | GET | без High | **High 1, Low 5, Medium 1** (усі інциденти) |
| анонім → search / summary | GET | 401 | **200** |

У browser client (вразливий стан) Alice бачила у списку 7 записів, серед них «O'Brien classroom report» Bob. Деталі цього інциденту з «автор: Боб Мельник» відображались.

**Першопричина.** Data-access path шукав `Incident` лише за `Id` (`.Where(incident => incident.Id == id)`). Між завантаженням і поверненням або зміною не було порівняння `OwnerUserId` з principal і не було жодного ресурсного рішення. Для triage не було перевірки ролі. Update DTO містив protected `Status`. Сам `id` в URL не є дефектом: дефект у тому, що сервер не перевіряв право.

## Виправлення та retest
Fixed commit: `e0f248873297aca1ad520ef9a46280ed91eb9621` (тег `v0.4.0`). Diff vulnerable → fixed: 10 файлів, 869 додавань, 114 видалень (`git diff --staged --stat`).

Ті самі запити після виправлення (після `--reset-database`):

| Сценарій | Фактично (fixed) |
|---|---|
| `login-and-read.py --user alice --incident bob` | `login_status=204`, `read_status=404`, `{"title": "Інцидент не знайдено", "status": 404, "traceId": …}` |
| Alice → своє / Alice → Bob / Alice → невідомий / Morgan → Alice / анонім | 200 / 404 / 404 / 200 / 401 |
| update (Alice → Bob) | PUT 404. Bob читає свій інцидент: title «Невідома спроба входу» — **не змінився** |
| delete (Alice → інцидент Bob) | DELETE 404. Bob читає: 200 — **на місці**. Bob як власник видаляє свій New → 204 |
| vertical: Alice triage власного New | **403** «Forbidden» з traceId; статус лишився `New` |
| vertical: PUT із `"status": "Closed"` | **400** «Bad Request»; статус `New`, title не змінився |
| Analyst Morgan: triage нового інциденту Alice | 200 `Triaged`; повторний triage → 409 «Перехід недоступний»; PUT → 403; Alice бачить статус `Triaged` |
| child: Alice → comment-2 / comment-3 / comment-1 | 404 «Коментар не знайдено» / 404 / 200 |
| child: Morgan → comment-3 (internal) | 200 |
| details-проєкція коментарів | Alice: тільки comment-1; Morgan: comment-1 і comment-3 |
| A-10: Alice → Bob і Alice → невідомий | обидва 404, `{"type", "title": "Інцидент не знайдено", "status": 404}`; відрізняється лише traceId |
| A-11: Alice search `q=O'Brien` / summary | `[]` / Low 5, Medium 1 (High відсутній) |
| A-11: Morgan search / summary | інцидент Bob …0004 / High 1, Low 6, Medium 1 |
| A-11: анонім search / summary | 401 / 401 |

Для mutation зафіксовано стан до і після: після кожної відмови стан Bob resource не змінився. Інтеграційні тести перевіряють те саме читанням із БД (`StateAsync`, `HistoryCountAsync`).

Для read: `IncidentDetailsResponse` не містить `ownerUserId`/`email`. Відповідь для чужого інциденту не містить ані title, ані id Bob (тест `A03_…`).

Узгодженість 404: один helper `IncidentNotFound()` використовується для details, update, delete, triage. Для коментарів — `CommentNotFound()`.

## Доказова таблиця
Автоматичні тести: `tests/SecureLab.Api.Tests/Lab04AuthorizationTests.cs` (15 тестів). Повний набір: **total 53, failed 0, succeeded 53** (`dotnet test … --configuration Release`, після reset).

| ID | Рівень | Сценарій | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|---|---|
| A-01 | добрий | Анонімний доступ | немає authentication context | GET details, list, summary, search, comment | `401`, не HTML redirect | 401 на всіх 5 маршрутах, `Location` відсутній, не `text/html`; сценарій: анонім → 401 | `A01_Anonymous_ProtectedIncidentRoutes_Return401_NotRedirect_NotHtml`; `lab04_scenarios.py read/a11` |
| A-02 | достатній | Власний ресурс | Alice, інцидент …0001 | GET details | allow | 200, id …0001, без `ownerUserId` | `A02_Details_AsOwner_ReturnsOwnIncident`; `login-and-read alice→alice` |
| A-03 | достатній | Чужий ресурс | Alice, інцидент Bob …0002 | GET details | 404 | 404 Problem Details, у тілі немає title/id Bob | `A03_Details_AsOtherReporter_ReturnsNotFound_WithoutBobData`; `login-and-read alice→bob` |
| A-03R | достатній | Аналітичний read | Morgan (Analyst), ресурс Alice | GET details | allow, без права mutation | 200; PUT/DELETE Morgan → 403 | `A03R_Details_AsAnalyst_ReturnsAliceIncident`, `A04_…AsAnalyst_ReturnForbidden…` |
| A-04 | добрий | Чужий ресурс, mutation | Alice, Bob resource | PUT, DELETE | deny, стан без змін | 404 і 404; стан Bob (owner, title, description, status) однаковий до/після | `A04_UpdateAndDelete_AsNonOwner_ReturnNotFound_AndDoNotChangeBobIncident`; сценарії update/delete |
| A-05 | добрий | List | Alice | GET /api/incidents | лише власні | немає …0002 і …0004; кожен рядок належить Alice (перевірка в БД); Morgan бачить обидва | `A05_List_AsReporter_ContainsOnlyOwnIncidents`; browser: 7 власних записів |
| A-06 | добрий | Вертикальне підвищення | Reporter Alice, власний New | POST triage | deny, статус без змін | 403 з traceId; статус New; записів історії 0 | `A06_Triage_AsReporterOwner_IsForbidden_AndStatusUnchanged`; сценарій vertical |
| A-07 | добрий | Дозволена привілейована дія | Morgan (Analyst), інцидент New | POST triage | allow | 200 Triaged, 1 запис історії; повтор → 409; Admin → 404 без зміни | `A07_Triage_AsAnalyst_NewToTriaged_ThenConflict_AdminHasNoImplicitRight`; сценарій analyst |
| A-08a | добрий | — | — | — | — | не виконувалось: обрано альтернативу A-08b | — |
| A-08b | добрий | Overposting: контракт відхиляє зайве поле | Alice, власний New | PUT з `ownerUserId`, `status`, `role`; triage з `status`, `isTransitionAllowed` | 400, protected state без змін | 400 `application/problem+json` для обох; стан однаковий до/після; дозволений update без зайвих полів → 200, owner/status незмінні | `A08b_Update_WithForgedOwnerRoleStatus_Returns400_AndProtectedStateUnchanged`, `Update_AsOwner_ChangesOnlyContent` |
| A-09 | добрий | Audit event | Alice → triage власного New | знайти `authorization.denied` | безпечна подія, той самий traceId | `warn: SecureLab.Audit … authorization.denied subject=10000000-0000-0000-0000-000000000001 action=incident.triage resource=90e4fba1-d2c3-450d-9d98-276425af4108 result=denied occurredAtUtc=2026-10-26T18:25:36.5476727+00:00 traceId=00-8721cbdda09e6245e8fe7d5bbdd0f9d9-d18aa3a821a97692-00`; той самий traceId у тілі 403 | вивід API + `lab04_scenarios.py audit` |
| A-10 | добрий | Нерозрізнюваність 404 | Alice; id Bob і випадковий id | два GET | однакові status, Content-Type, тіло без traceId | обидва 404 `application/problem+json`, JSON рівні після вилучення traceId | `A10_ForeignAndUnknownIncident_AreIndistinguishable`; сценарій a10 |
| A-11 | відмінний | search і severity-summary | Alice / Morgan | `search?q=O'Brien`, `severity-summary` | лише дозволена множина | Alice: `[]`, без High; Morgan: інцидент Bob, High 1; анонім: 401 | `A11_SearchAndSeveritySummary_AsReporter_DoNotRevealForeignIncidents`; сценарій a11 |
| A-12 | добрий | Child resource та internal comment | Alice; comment-2 (Morgan → інцидент Bob), comment-3 (internal) | GET `/api/incident-comments/{id}`, details-проєкція | 404; internal не потрапляє Reporter | comment-2 → 404, comment-3 → 404, comment-1 → 200; у details Alice немає comment-3; Morgan бачить comment-3 | `A12_CommentsAndInternalComment_FollowParentAndRole`; сценарій child |

## Основний finding і залишковий ризик (усі рівні)
1. **Контекст.** Ресурс `Incident` (baseline 2-A); дії: details, update, delete, triage. Суб'єкти — штучні Alice, Bob (Reporter), Morgan (Analyst), Admin на локальному стенді.
2. **Гіпотеза.** Alice, змінивши лише id в URL, прочитає, змінить чи видалить інцидент Bob, а як Reporter виконає privileged transition.
3. **Стан до.** Vulnerable commit `cdf6e751922e28f77ba0c5be1c528e969329ec7f`. Alice → Bob: `read_status=200` і дані Bob; PUT змінив title Bob; DELETE видалив інцидент Bob; triage Reporter-а → 200; `status: Closed` через update спрацював.
4. **Першопричина.** `IncidentQueries.GetDetailsAsync` і нові mutation endpoint-и завантажували entity лише за `Id`. Порівняння з principal і ресурсного рішення не було, як і перевірки ролі для triage. Update DTO містив `Status`.
5. **Виправлення.** Resource-based `IncidentAuthorizationHandler` з операціями Read, ReadInternalComments, Update, Delete, Triage. Endpoint-и викликають рішення до будь-якої відповіді чи `SaveChangesAsync`. Множини фільтруються через `VisibleTo`. DTO звужено до content-полів із `Disallow`.
6. **Retest.** Той самий запит Alice → Bob дає 404, а стан Bob не змінився. Reporter-triage дає 403 без зміни статусу. Overposting дає 400.
7. **Позитивна регресія.** Alice читає й редагує власний інцидент (200) і видаляє власний New (204). Morgan читає інцидент Alice і виконує triage New → Triaged (200). Створення з owner із principal працює (тести ЛР 2–3 зелені).
8. **Залишковий ризик.**
   - CSRF для cookie-authenticated mutation (PUT/DELETE/triage) лишається задокументованим навчальним боргом ЛР 3 до ЛР 6 (SameSite=Lax — лише часткова мітигація).
   - Concurrent transitions (два Analyst одночасно) не перевірялись: сценарію від викладача немає.
   - Batch/export endpoint-ів у проєкті немає.

Схема рішення: запит Alice з id → cookie формує перевірений principal → `IncidentViewer` (id і роль із claims) → завантажений `Incident` або обмежений запит `VisibleTo` → `IncidentAuthorizationHandler` (owner / роль / статус) → дозвіл або 404 (невидимий), 403 (видимий без права), 409 (невірний статус) → відповідь. Mutation виконується лише після дозволу.

## Browser flow (усі рівні)
Alice входить на `auth-lab.html` і переходить на головну сторінку.
- **Вразливий стан:** список 7 записів, серед них інцидент Bob; його details відкривались.
- **Після виправлення:**
  - список містить лише 7 інцидентів Alice (seed і створені сценаріями);
  - details власного інциденту відображаються;
  - `loadIncidentDetails("20000000-0000-0000-0000-000000000002")` у DevTools Console дає `GET …/api/incidents/20000000-…0002 404 (Not Found)`, і клієнт показує відмову сервера.

Клієнт `app.js` виводить дані через `createTextElement(...)` / `textContent` (тест `ClientScript_DoesNotUseDangerousInnerHtmlSink`). Авторизацію він не виконує, лише показує рішення сервера. Значень cookie та пароля на знімках немає.

## Добрий рівень: роль, transition, child, audit
- **Transition.**
  - Наступний статус визначає сервер у `TriageAsync`: `incident.Status = IncidentStatus.Triaged`. Він же додає запис `IncidentStatusHistory` із `ChangedByUserId` з principal.
  - Роль зчитується лише з claim (`IsInRole(Analyst)` у `IncidentViewer`).
  - Порядок: tracked entity → рішення Triage → при deny audit і 403/404 → перевірка `Status == New` (інакше 409) → зміна → `SaveChangesAsync`.
  - Статус у JSON не може бути дозволом: клієнт контролює body, тому контракт його не приймає (400).
- **Child.**
  - `GET /api/incident-comments/{id}` завантажує коментар разом із parent `Incident` і вимагає Read для parent.
  - Для internal comment додатково потрібна ReadInternalComments (лише Analyst).
  - Те саме правило застосовано в details-проєкції: `includeInternalComments || !comment.IsInternal`. До виправлення internal comment бачила навіть Alice через прямий id, а Analyst не бачив його в details.
- **Audit.**
  - Поля: subject (з principal), action, resource, result, occurredAtUtc (сервер), traceId = `Activity.Current?.Id ?? httpContext.TraceIdentifier`. Той самий traceId потрапляє в Problem Details відповіді (доказ A-09).
  - Cookie, password, token і request body не логуються.

## Відмінний рівень
- **Handler.** `IncidentAuthorizationHandler` винесено в окремий файл `IncidentAccess.cs`. Усі рішення для окремого ресурсу (details, update, delete, triage, child) проходять через `IAuthorizationService`. Для множин те саме правило виражене як `VisibleTo`.
- **Додатковий finding A-11 (search і severity-summary).**
  - Контекст: endpoint-и ЛР 1–2 `GET /api/incidents/search` і `GET /api/incidents/severity-summary`.
  - Гіпотеза: навіть із захищеним details Reporter отримає дані чужих інцидентів через пошук і агрегацію.
  - Стан до (vulnerable `cdf6e75…`): Alice за `q=O'Brien` отримала інцидент Bob …0004; summary містило High 1 (єдиний High — інцидент Bob); анонім отримував 200 на обох маршрутах.
  - Першопричина: обидва запити не мали умови за суб'єктом, а search не мав `.RequireAuthorization()`.
  - Виправлення: `.RequireAuthorization()` на search (summary — через групу) і `.VisibleTo(viewer)` у самому SQL-запиті — до сортування й `Take(50)` у пошуку, до `GroupBy` у зведенні. Нових endpoint-ів не створено.
  - Після: Alice `[]` і зведення без High; Morgan бачить інцидент Bob і High 1; анонім 401. Регресія ЛР 2: механіку пошуку перевірено від імені Analyst (його множина — усі інциденти), тести S-02, T-04, T-05 зелені.
- **A-08b і A-06** підтверджують захист privilege-related field і регресію вертикального підвищення. Повторних тестів не створювалось.
- **Видимість ресурсу.**
  - Reporter не повинен дізнатися навіть про існування чужого інциденту (назва інциденту безпеки — чутлива), тому чужий = неіснуючий (404, той самий helper, A-10).
  - Тому, хто ресурс бачить, явний 403 пояснює, що бракує права саме на дію. Існування ресурсу тут не секрет.
- **Least privilege.**
  - Reporter: створює й редагує лише власне — він автор повідомлення.
  - Analyst: читає все, бо його обов'язок — класифікувати. Із привілейованих дій має лише New → Triaged; не редагує чужий текст і не видаляє, бо це не потрібно для аналізу.
  - Administrator: у предметному правилі 2-A не має названих прав над інцидентами, тому роль не дає обходу ownership.
  - Delete дозволено лише власнику до початку обробки (New), щоб не знищувати записи, з якими вже працює аналітик.
- **Охоплення та залишкові ризики.**
  - Охоплено всі наявні маршрути Incident та IncidentComment.
  - Batch/export: не застосовується, таких flow немає.
  - Concurrent transitions: не застосовується, сценарій не надано; можливий захист — optimistic concurrency token.
  - CSRF: навчальний борг до ЛР 6.
  - Перевірки виконано лише на штучних seed-даних локального стенда.

## Перевірки, відтворення і подання
- **Середовище:** Windows 11, PowerShell, .NET 10 SDK, PostgreSQL у Docker (`secure-lab-postgres-1 Healthy`), API `http://localhost:5080`.
- **Стартові перевірки:**
  - гілка від `v0.3.0`;
  - `login-and-read.py --check` → `{"password_present": true, "json_valid": true}`;
  - reset;
  - `dotnet test` → 38/38;
  - Alice /api/me → id …0001 (Reporter), Morgan → id …0003 (Analyst);
  - «Мій профіль» без login → 401;
  - анонімний `POST /api/incidents` → `HTTP/1.1 401 Unauthorized`;
  - SQL ролей → admin | Administrator, alice | Reporter, bob | Reporter, morgan | Analyst.
- **Команди:**
  ```powershell
  docker compose --env-file infra/.env.example -f infra/compose.yaml up -d --wait
  dotnet run --project src/SecureLab.Api -- --reset-database
  dotnet build SecureLab.sln -c Release
  dotnet test tests/SecureLab.Api.Tests/SecureLab.Api.Tests.csproj --configuration Release
  dotnet run --project src/SecureLab.Api --launch-profile http
  py -3 ../lr04-resources/commands/login-and-read.py --user alice --incident bob
  py -3 tests/http/lab04_scenarios.py read|update|delete|vertical|analyst|child|a10|a11|audit
  ```
- **Після виправлення:** build succeeded; **tests: total 53, failed 0, succeeded 53** (13,4 s).
- **Відновлення:** після PoC на vulnerable commit (змінено title Bob і видалено тестовий запис) виконано `--reset-database` перед retest.
- **Тег:** `v0.4.0` → commit `e0f248873297aca1ad520ef9a46280ed91eb9621` (annotated, 2026-10-26). Hash вписано окремим наступним commit «Record lab 4 hashes». Гілка `lab/4-authorization` і тег передаються до приватного repository.
- **Невиконане / обмеження:**
  - A-08a (обрано A-08b);
  - concurrent transitions (сценарію немає);
  - export/batch (flow немає);
  - зміна SDK у `global.json` не знадобилась.

## Використання ШІ
Використав Claude (Anthropic) дозволеним способом.

| Дата/інструмент | Для чого | Що використано | Що перевірено самостійно |
|---|---|---|---|
| 26.10.2026, Claude | розбір методички й покроковий план; чернетка матриці; код handler/endpoint-ів/DTO; тести A-01…A-12; сценарій `lab04_scenarios.py`; чернетка звіту | `IncidentAccess.cs`, `IncidentEndpoints.cs`, `IncidentQueries.cs`, `IncidentRequests.cs`, зміни `Lab02Endpoints.cs`, `Program.cs`, тестів | build і 53/53 тести у власному середовищі; ручний PoC до/після; browser flow; збіг traceId в audit і відповіді; відсутність секретів на скрінах; окремі vulnerable і fixed commits |

Паролі, cookie та реальні персональні дані ШІ не передавались. Пароль задавався лише змінною середовища.
