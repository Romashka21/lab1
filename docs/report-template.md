# Звіт до лабораторної роботи № 2

Контракт API, серверна валідація та захист від SQL injection. Варіант 2-A «Трекер інцидентів».

> Рядки з позначкою **⚠️ ДОДАТИ** потребують скріна або перевірки, яких немає в наявному комплекті доказів. Перед здачею їх треба виконати й прибрати позначку.

## 1. Ідентифікація стану

- Варіант: 2-A «Трекер інцидентів».
- Гілка: `lab/2-input-sqli`.
- Фінальний тег: `v0.2.0` (на останньому коміті зі звітом).
- Commit hash виправлення (fixed): `7bae48b23d23effa1c872e5aa9ab559e3bd2bdf0`.
- Commit hash вразливого стану (vulnerable): `fbb9367e32244cb30e9c18629deb382a7619d242`.
- Вхідний стан: тег `v0.1.0`, base commit `5b584b9d6289886da9c7495b9d3922a719bc6682`.
- Scaffold: release ID `lab-02-start-v1`.
- Середовище: локальний `Development`, PostgreSQL з `infra/compose.yaml`, штучні seed-дані, .NET 10.



## 2. Змінений маршрут

**Створення інциденту (`POST /api/incidents`).** JSON із клієнта → `CreateIncidentRequest` (окремий request DTO) → серверна валідація (required, довжина 160/4000 до `Trim()`, `Enum.TryParse` разом з `Enum.IsDefined`, дата не далі ніж +5 хв від серверного UTC) → cross-field правило для High/Critical → додаткове правило T-10 → предметна перевірка дубліката `AnyAsync` (409) → створення `Incident` із server-managed полями (`Id`, `OwnerUserId`, `Status`, `CreatedAtUtc`, `UpdatedAtUtc` ставить сервер) → `SaveChangesAsync` → `CreatedIncidentResponse` (201). Ключовий файл: `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs`.

**Пошук (`GET /api/incidents/search?q=…&sortBy=…`).**
- До виправлення: query string → параметри `q` і `sortBy` → конкатенація в текст SQL (`Lab02Endpoints.cs`, рядок 22) → `db.Incidents.FromSqlRaw(sql)` (рядок 25) → PostgreSQL.
- Після виправлення: `sortBy` проходить allowlist (`createdAtUtc`, `severity`, `status`, інакше 400) → значення `q` екранується (`%`, `_`, `\`) і передається окремим параметром у LINQ-запит із `EF.Functions.ILike` → `Take(50)` → `IncidentListItemResponse`.

## 3. Виконані зміни

1. Окремі DTO: `CreateIncidentRequest` (лише `title`, `description`, `severity`, `occurredAtUtc`) і `CreatedIncidentResponse` (без внутрішніх полів). Клієнт не може передати `OwnerUserId`, `Status`, `Id`, часи створення.
2. Базові правила 2-A на сервері: required, довжини 160/4000, enum, дата не пізніше +5 хв, нормалізація `Trim()` один раз, UTC (`ToUniversalTime()`).
3. Cross-field T-09: для `High`/`Critical` опис після `Trim()` не коротший за 40 символів, помилка з ключем `description`.
4. Предметний конфлікт T-03: активний дублікат за `title` (з урахуванням регістру) дає 409. Статуси New, Triaged, InProgress, Resolved блокують створення, Closed не блокує.
5. Додаткове правило T-10 (відмінний рівень): `description` після `Trim()` не може збігатися з `title`, повертається 400 з ключем `description`.
6. Єдиний формат помилок: Problem Details (`application/problem+json`) для 400, 404 і 409.
7. Виправлено першопричину SQL injection: LINQ з `EF.Functions.ILike` і значенням `q` як параметром, екранування метасимволів `LIKE`; `sortBy` вибирає структуру запиту через allowlist. Другий ключ сортування `Id`, `Take(50)` після сортування.
8. Додатково відсікається `severity` зі списком через кому (наприклад `"Medium, High"`), який `Enum.TryParse` інакше приймає.
9. Додано автоматичні тести `tests/SecureLab.Api.Tests/Lab02SecurityTests.cs` (16 тестових випадків) із очищенням створених даних у `finally`.

## 4. Перевірка

| ID | Передумови | Дія | Очікувано | Фактично | Доказ |
|---|---|---|---|---|---|
| T-01 | Reset seed, унікальний title | `POST /api/incidents` з коректним DTO (`Унікальний конфлікт`, Medium) | 201, response DTO без зайвих полів | 201 Created; у відповіді `id`, `title`, `severity`, `status = New`, `occurredAtUtc`, `createdAtUtc`; внутрішніх полів немає | `evidence/t01-created-201.png` |
| T-02 | — | `POST` з `severity: "7"` | 400, `application/problem+json`, помилка по `severity` | 400; `errors.severity`: «Допустимі значення: Low, Medium, High, Critical.»; stack trace, SQL і внутрішніх назв немає | `evidence/t02-severity7-400.png` |
| T-03 | Існує активний інцидент з тим самим `title` | Повторний `POST` з тим самим `title` | 409 у Problem Details | Покрито автотестом `T03_DuplicateActiveTitle_Returns409` (набір 21/21 пройдено). Скрін ручного 409 з `lab-02-checks.http` наведено у PDF-звіті. | `evidence/tests-21-passed.png` |
| T-04 | Fixed commit, reset | Звичайний пошук (`q=USB`), пошук з апострофом (`q=O'Brien`, `q=комп'ютерного`) | Коректні записи, без 500 | `USB` повертає 1 запис (…0005); `O'Brien` повертає 200 і запис «O'Brien classroom report» (…0004); `комп'ютерного` повертає 200 і запис …0003 | `evidence/s02-A-after.png`, `evidence/s02-D-after.png`, `evidence/t04-komputerny.png` |
| T-05 | Fixed commit | `GET /api/incidents/search?sortBy=price` | 400 | 400 Problem Details, `errors.sortBy`: «Допустимі значення: createdAtUtc, severity, status.» | `evidence/t05-sortby-price-400.png` |
| T-06 | Синтаксично коректний, але відсутній id | `GET /api/incidents/99999999-9999-9999-9999-999999999999` | 404 у Problem Details | 404; `title`: «Інцидент не знайдено»; `detail` називає запитаний id; деталей БД немає | `evidence/t06-404.png` |
| T-09 | Унікальні `title`, решта полів коректна | `POST` із `severity: High` і описом із 39 символів; повтор із 40 символами | Перший 400 по `description`, другий проходить | 39 символів: 400, `errors.description`: «Для рівнів High та Critical опис має містити щонайменше 40 символів.» Скрін 201 для 40 символів (або запис із автотесту `T09_…`) наведено у PDF-звіті. | `evidence/t09-high-39-400.png` |
| T-10 | Правило: `description` не збігається з `title` | `POST` з `title` = `description` = «Один в один» | 400, ключ `description`; допустимий запит проходить | 400, `errors.description`: «Опис не може повністю збігатися з назвою інциденту.»; допустимий випадок (опис відрізняється) дає 201 | `evidence/t10-same-text-400.png`, `evidence/t01-created-201.png` |
| S-01 | Vulnerable commit, reset | Контрольний read-only сценарій C: `q=zz-no-match' OR TRUE -- ` | Небажано розширена вибірка | 200 і всі 5 seed-записів замість `[]` | `evidence/s01-C-before.png` |
| S-02 | Fixed commit, той самий seed | Той самий сценарій C | Порожній результат | 200 і `[]`; автотест `S02_ControlInput_ReturnsEmptyList_…` пройшов, позитивний контроль `q=USB` повертає єдиний запис …0005 | `evidence/s02-C-after.png`, `evidence/tests-21-passed.png` |
| A-01 | Fixed commit | `git grep` за `FromSqlRaw`, `ExecuteSqlRaw`, `ORDER BY` та огляд LINQ | Усі точки доступу до даних із висновками | Див. таблицю у 4.2 | `a01-before.txt`, `a01-after.txt` |
| A-02 | Fixed commit | `POST` із зайвими `id`, `status: "Closed"`, `ownerUserId` | Запис із серверними значеннями | 201; новий `id` (не надісланий), `status = New`; автотест `A02_Overposting_…` пройшов. Скрін експерименту «до» (тимчасове поле `Status`, тест падає з `Expected: "New"`, `Actual: "Closed"`) наведено у PDF-звіті. | `evidence/a02-overposting-201.png` |

Запуск повного набору тестів (reset перед прогоном): `Test summary: total: 21; failed: 0; succeeded: 21`. Скрін із назвами тестів (`dotnet test … --logger "console;verbosity=normal"`) наведено у PDF-звіті.



Сортування (штатний seed після reset):

| Запит | Фактичний порядок | Збігається з контрактом |
|---|---|---|
| без `sortBy` | …0004 → …0005 → …0003 → …0002 → …0001 | так |
| `sortBy=severity` | …0002 High → …0001 Medium → …0003, …0004, …0005 Low | так |
| `sortBy=status` | …0003, …0004, …0005 New → …0001 Triaged → …0002 InProgress | так |



### 4.1 Контрольні точки

**CP-01. Перевірений контракт створення.** Змінений `POST /api/incidents` приймає лише `CreateIncidentRequest`. Запит із `severity: "7"` відхиляється: `Enum.TryParse` приймає числовий рядок і повертає `true`, тому одного його недостатньо, а `Enum.IsDefined` перевіряє приналежність значення до набору `Low`, `Medium`, `High`, `Critical`. Маршрут «JSON → DTO → server-side validation → 400 Problem Details» виконується до звернення до БД, тому `<select>` у браузері не замінює цієї перевірки: клієнт може надіслати будь-яке тіло. `CreateIncidentRequest` не містить `OwnerUserId` і `Status`, тому клієнт не може передати їх до моделі створення: `Status = New` і `OwnerUserId = DbSeeder.AliceId` ставить сервер. Докази: `evidence/t02-severity7-400.png`, `evidence/a02-overposting-201.png` (зайві поля ігноруються), код `evidence/cp01-post-code-1.png`, `-2`, `-3`. Для доброго рівня додано T-03 і T-09.



**CP-02. Доказ першопричини SQLi.** Vulnerable commit: `fbb9367e32244cb30e9c18629deb382a7619d242`. Точка складання SQL: `src/SecureLab.Api/Scaffolding/Lab02Endpoints.cs`, обробник `GET /api/incidents/search`, рядок 22 (`var sql = "SELECT … ILIKE '%" + (q ?? "") + "%' … ORDER BY " + sortExpression`), виконання — рядок 25 (`db.Incidents.FromSqlRaw(sql)`). Маршрут: query string `q`/`sortBy` → параметри обробника → конкатенація → `FromSqlRaw` → PostgreSQL.

Спостереження (власний read-only сценарій, local seed):

| Поле | Спостереження |
|---|---|
| Передумови | local `Development`, контейнер PostgreSQL, reset, vulnerable commit |
| Дія | `GET /api/incidents/search?q=…`: A `USB`, B `zz-no-match`, C `zz-no-match' OR TRUE -- `, D `O'Brien` |
| Очікування без дефекту | пошук не повертає записи, що не відповідають значенню |
| Фактичне спостереження | A: 200, 1 запис (…0005). B: 200, `[]`. C: 200, усі 5 seed-записів (…0001–…0005). D: 500 Problem Details без внутрішніх деталей (клієнту повертається лише загальне повідомлення) |
| Пояснення | В C апостроф закрив рядковий літерал, `OR TRUE` став частиною умови `WHERE` (завжди істинна), а `--` закоментував решту. В D апостроф закрив літерал, а `Brien%'` залишилося поза лапками, і PostgreSQL повернув помилку синтаксису 42601 |



Серверний журнал для D: `Failed executing DbCommand … [Parameters=[], …]` і `42601: syntax error at or near "Brien"`; стек вказує на `Lab02Endpoints.cs:line 25`. Значення не передано окремо від тексту SQL (`Parameters=[]`).



Скрін журналу `Executed DbCommand … [Parameters=[], …]` для запитів B і C до виправлення (повний рядок із текстом команди), що показує різницю між B і C, наведено у PDF-звіті.

Чому фільтр апострофа або `OR …` не усуває першопричину: він блокує лише один payload, а значення все одно конкатенується зі структурою запиту; інший ввід знову змінить SQL. Усунення потребує окремої передачі значення і явного allowlist для структури. Запланований механізм: LINQ з `EF.Functions.ILike` і `sortBy` через `switch`.

**CP-03. Перевірений механізм виправлення.** Різниця між vulnerable (`fbb9367…`) і fixed (`7bae48b…`) commit: 2 файли, 406 додавань, 40 видалень (`Lab02Endpoints.cs`, новий `Lab02SecurityTests.cs`); повний diff — `docs/evidence/security.diff`. Було: значення `q` і `sortBy` потрапляли в єдиний текст SQL після конкатенації. Стало: значення `q` екранується і передається окремим параметром (`@pattern`) в `ILIKE … ESCAPE '\'`, а структуру сортування вибирає серверний allowlist. Після виправлення ті самі запити: A повертає той самий запис, B і C повертають `[]`, D повертає 200 і запис «O'Brien classroom report».



Скрін журналу API після виправлення для запиту B (наведено у PDF-звіті): `Executed DbCommand … [Parameters=[@pattern='?', …]]` і в тексті SQL `ILIKE @pattern ESCAPE '\'`. Цей запис разом із журналом до виправлення є доказом механізму «значення в тексті» проти «значення окремо».

### 4.2 Огляд data-access points (A-01)

Пошук `git grep -n -e FromSqlRaw -e ExecuteSqlRaw -e "ORDER BY" -- src tests` на vulnerable commit знайшов три місця; на fixed commit залишилося одне.

| Файл:метод | Категорія | Висновок |
|---|---|---|
| `Data/DatabaseBootstrap.cs:29` (`ExecuteSqlRawAsync`) | trusted static SQL | Статичний службовий SQL без користувацьких значень; залишається на fixed commit. **⚠️ ДОДАТИ:** перевірити вмістом методу перед здачею |
| `Scaffolding/Lab02Endpoints.cs:22, 25` (пошук, vulnerable) | raw SQL з конкатенацією | Небезпечно (значення і структура в одному тексті). **Усунено** на fixed commit |
| `Scaffolding/Lab02Endpoints.cs` (пошук, fixed) | LINQ, `EF.Functions.ILike` | Безпечно: `q` іде параметром, `sortBy` перевіряється allowlist |
| `Scaffolding/Lab02Endpoints.cs` (POST, перевірка дубліката) | LINQ `AnyAsync` | Безпечно: порівняння `Title` параметризується EF Core |
| `Scaffolding/Lab02Endpoints.cs` (POST, створення) | EF Core `Add` + `SaveChangesAsync` | Безпечно: параметризований INSERT, серверні поля |
| Інші обробники з ЛР 1 (за наявності) | **⚠️ ДОДАТИ** | Виконати `git grep -n -e "db\.Incidents" -e "DbContext" -- src` і внести кожен збіг |

## 5. Security-сценарій

1. **Контекст і гіпотеза.** Локальний endpoint пошуку отримує недовірені `q` і `sortBy`; існує ризик, що значення потрапляє в структуру SQL-запиту.
2. **Стан «до».** Vulnerable commit `fbb9367e32244cb30e9c18629deb382a7619d242`; метод — обробник `GET /api/incidents/search` у `Lab02Endpoints.cs`; SQL збирається у рядку 22 конкатенацією `q` і `sortExpression`, виконується в рядку 25 через `FromSqlRaw`.
3. **Мінімальний PoC.** Власний read-only сценарій C: `GET /api/incidents/search?q=zz-no-match' OR TRUE -- ` (URL-кодований). Це єдиний контрольний ввід, інших payload не застосовувалось; модифікуючі команди не виконувались.
4. **Спостереження.** B (значення, якого немає) повертає `[]`, C повертає усі 5 seed-записів: множина результатів розширилась. Легітимний апостроф (D) дає 500 з помилкою PostgreSQL 42601 у журналі.
5. **Першопричина.** `q` (і `sortBy`) зʼєднувались із SQL-текстом до виконання; СУБД не відрізняла дані від інструкції.
6. **Виправлення.** LINQ з `EF.Functions.ILike` і екрануванням метасимволів, значення `q` передається параметром; `sortBy` вибирає структуру через allowlist; серверна валідація контракту створення.
7. **Retest і позитивна регресія.** Той самий сценарій C повертає `[]`; A повертає той самий запис; легітимні слова з апострофом (`O'Brien`, `комп'ютерного`) повертають 200 і відповідні записи; невідомий `sortBy` дає 400. Автоматичні тести: 21/21 пройдено.
8. **Залишковий ризик.** Перевірка не змінює authorization (власник інциденту фіксований як Alice до ЛР 3), не обмежує ресурс паґінацією (є лише `Take(50)`), не охоплює інші endpoint-и поза огляду A-01 і production logging policy.

## 6. Висновок

Контракт створення інциденту обмежено окремим request DTO із серверною валідацією (формат, діапазон, cross-field правило T-09, предметний конфлікт T-03, правило T-10); некоректний вхід повертає 400 у форматі Problem Details без внутрішніх деталей, а server-managed поля (`Id`, власник, статус, часи) визначає лише сервер. Вразливий пошук відтворено на окремому vulnerable commit (контрольний ввід C повертав усі 5 seed-записів, легітимний апостроф давав 500) і усунено заміною конкатенації на LINQ-запит із параметризованим значенням та allowlist для `sortBy`; після виправлення той самий сценарій повертає `[]`, а легітимні запити з апострофом працюють. Підтвердження — ручні запити та 21 автоматичний тест, усі пройдені.

## 7. Обмеження

- Для `POST /api/incidents` перевірка дубліката через `AnyAsync` навчальна: вона не гарантує інваріант за одночасних запитів. У реальному застосунку потрібно узгоджене обмеження БД або транзакційне рішення; migration або унікальний індекс у цій ЛР не додавались.
- Некоректний (зіпсований) JSON у стартовому конвеєрі дає 500 через `BadHttpRequestException` — це окремий дефект обробки, який у цій ЛР не виправлявся.
- Authorization не реалізовано: власник нового інциденту фіксований (Alice), справжній principal з'явиться в ЛР 3.
- Пагінації немає: `Take(50)` лише обмежує розмір вибірки.
- Усі перевірки виконано локально на штучних seed-даних.

## 8. Декларація використання генеративного ШІ

- **Сервіс:** Claude (Anthropic).
- **Задачі:** звірка виконаних кроків і скріншотів із критеріями методички; чернетки виправленого коду пошуку і POST-обробника, тестового класу `Lab02SecurityTests.cs`, ручних `.http`-сценаріїв, послідовності Git-команд і чернетка цього звіту.
- **Власна адаптація:** підлаштовано `using` і типи під структуру власного проєкту (`SecureLab.Api.Data.Entities`), виправлено помилки збірки (CS0234, CS0165), відновлено Git-історію (окремі vulnerable і fixed commits), усі запити й тести запущено локально.
- **Фактична перевірка:** `dotnet build`, `dotnet test` (21 з 21), ручні запити T-01…T-10 і A–D до і після виправлення, `git diff` між vulnerable і fixed commit. Згенерований код і твердження перевірено власними запусками.