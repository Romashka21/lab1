# Захист ЛР 4 — BOUND-WEB04: X-Total-Count для пошуку

## 0. Контракт і пропозиція, що перевіряється
- Пошук `GET /api/incidents/search?q=…`: тіло — лише перша сторінка, `Take(50)`.
- Контракт total: `X-Total-Count` = кількість **доступних** principal-у q-збігів **до** `Take(50)`, без обмеження 50.
- Пропозиція `X-Total-Count = items.Count` хибна. `items` уже обрізані лімітом, тож це розмір сторінки, а не total.
- Хибна й протилежна крайність: рахувати всі q-збіги без scope. Тоді total розкриває кількість чужих записів (IDOR через агрегат).

## 1. Ручний прогноз (зафіксовано ДО запуску)
Набір BOUND-WEB04: 51 збіг Alice, 7 збігів Bob, усього 58; limit 50. Morgan (Analyst) показано довідково.

| Суб'єкт | доступні q-збіги | items (тіло) | total (контракт) | mutant `items.Count` | mutant «count усіх» |
|---|---:|---:|---:|---:|---:|
| Alice | 51 | 50 | **51** | 50 ✗ | 58 ✗ |
| Bob | 7 | 7 | **7** | 7 (випадково ✓) | 58 ✗ |
| Morgan (довідково) | 58 | 50 | 58 | 50 ✗ | 58 (випадково ✓) |

Межі для Alice (Bob завжди 7):

| Доступні збіги Alice | items | total | `items.Count` | count усіх (N + 7) |
|---:|---:|---:|---|---:|
| 49 | 49 | 49 | 49 — випадково правильний | 56 ✗ |
| 50 | 50 | 50 | 50 — випадково правильний | 57 ✗ |
| 51 | 50 | 51 | **50 — помилка** | 58 ✗ |

`items.Count` випадково правильний, коли доступних збігів ≤ 50: тоді `Take(50)` нічого не відрізає. Помилка проявляється лише з 51-го доступного рядка, тому тест мусить мати межу 51.

## 2. Рішення
Окремий count-query по **тому самому** `IQueryable found` (scope `VisibleTo(viewer)` + match `ILike` для title і description), без `OrderBy` і `Take`. Сторінка далі будується з `found` → сортування → `Take(50)`.

Спільні умови сторінки й count (обидва SQL мають однаковий WHERE):
```sql
-- count (новий запит)
SELECT count(*)::int FROM incidents AS i
WHERE (@isAnalyst OR i.owner_user_id = @userId)
  AND (i.title ILIKE @pattern ESCAPE '\' OR i.description ILIKE @pattern ESCAPE '\')

-- сторінка (наявний запит)
SELECT i.id, i.title, … FROM incidents AS i
WHERE <той самий WHERE>
ORDER BY i.created_at_utc DESC, i.id
LIMIT @p
```
Фактичний SQL взяти з логу API (`Microsoft.EntityFrameworkCore.Database.Command`). Npgsql може спростити `@isAnalyst OR` для Reporter.

## 3. Regression
`tests/SecureLab.Api.Tests/Lab04SearchTotalTests.cs`:
- `BoundWeb04_AliceSearch_PageCappedAt50_TotalCountsAccessibleMatches(49|50|51)`: сторінка ≤ 50, лише рядки Alice, жодного Bob; `total == N`.
- `BoundWeb04_BobSearch_PositiveControl_SevenOwnMatches_NoAliceRows`: 7 / 7, жодного рядка Alice.

Два незалежні count-контролі:
1. Ручний прогноз, тобто розмір набору: `Assert.Equal(aliceMatches, total)`.
2. Окремий запит до БД з явним owner (`CountOwnMatchesInDbAsync`), який не залежить від коду API.

Assertion, що відхиляє обидва mutant-и: `Assert.Equal(51, total)` для Alice при N = 51. Mutant `items.Count` дає 50, «count усіх» — 58. Для Bob `Assert.Equal(7, total)` відхиляє «count усіх» (58).

## 4. Спостереження (заповнити фактичними значеннями)
| Перевірка | Тип | Фактично |
|---|---|---|
| Alice, `bound` до зміни | HTTP | body … ; X-Total-Count … |
| Alice, `bound` після зміни | HTTP | body … ; X-Total-Count … ; чужих … |
| Bob, `bound` після зміни | HTTP | body … ; X-Total-Count … ; чужих … |
| Тести Lab04SearchTotalTests | unit/integration (HTTP + БД) | … passed |
| Mutant `items.Count` | integration | падає: Expected 51, Actual … |
| Mutant «count без VisibleTo» | integration | падає: Expected 51, Actual … |
| SQL count і page з логу API | SQL | однаковий WHERE: … |

## 5. Залишковий ризик
- Count і сторінка — два окремі запити без спільної транзакції. Якщо між ними хтось вставить запис, total може розійтися з реальним станом на 1. Для пагінації це прийнятно; за потреби — repeatable read або один запит з `count(*) OVER ()`.
- Сторінок, крім першої, ще немає (немає `skip`/`page`). Total описує всю дозволену множину.
