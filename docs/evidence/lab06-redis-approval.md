# Погодження advanced variant ЛР 6 (Redis)

Студент: Дриг Роман Андрійович, КБ-43. Отримано: 2026-11-11 00:30 (Europe/Kyiv), Moodle.
Запит: розподілений rate limiting `GET /api/incidents/search` через Redis (окремий контейнер на 127.0.0.1,
StackExchange.Redis, лічильник fixed window + TTL, partition = id користувача, fail-safe на локальний limiter).

## Відповідь викладача (дослівно)

> Погоджую Redis-сценарій як advanced variant ЛР 6. Fail-safe з переходом на локальний limiter приймаю, якщо обґрунтуєте його в звіті. Під час реалізації врахуйте:
>
> 1. Номер вікна в ключі не рахуйте за годинником екземпляра: при розбіжності часу екземпляри писатимуть у різні ключі. Беріть час із Redis (TIME у Lua) або відлічуйте вікно від першого запиту (INCR + EXPIRE при значенні 1). Сценарій «3 + 2 → 429» не повинен розриватися межею вікна.
> 2. Не прив'язуйте Redis лише до Development: вмикання через конфігурацію в будь-якому профілі, демонстрація двох екземплярів у production-like, а якщо Redis не налаштовано — явний warning під час старту.
> 3. Для fail-safe покажіть: під час простою Redis ліміт на одному екземплярі все ще дає 429; пошук не чекає таймауту на кожному запиті (пауза перед повторним підключенням); warning пишеться один раз на відмову; після docker start лічильник знову спільний. Те, що локальний лічильник стартує з нуля, опишіть у residual risk.
> 4. Автоматизуйте щонайменше один тест із живим Redis і тест fallback (недоступний Redis → не 500, після квоти 429).
> 5. Квота має відповідати вашому наявному search limiter або узгоджено оновіть регресію. Опишіть, як limiter вбудовано в наявний AddRateLimiter і чи однаковий формат 429 (Retry-After).
> 6. Вхід Alice виконуйте окремо на 5080 і 5081, щоб довести, що partition — id користувача, а не cookie.
>
> Цю відповідь збережіть у доказах звіту. Не забудьте декларацію використання ШІ. Погодження стосується лише розширення: решта вимог відмінного рівня лишається.

## Як враховано кожну умову

| № | Умова | Реалізація | Доказ |
|---|---|---|---|
| 1 | вікно не за годинником екземпляра | ключ `securelab:rl:search:user:{id}` без номера вікна; Lua: `INCR`, для значення 1 — `PEXPIRE`; захист ключа без TTL | `RedisSearchRateLimiter.cs` (Lua), REG-REDIS-02, `TTL` у redis-cli |
| 2 | будь-який профіль; production-like; warning без Redis | `RateLimit:Search:Redis:ConnectionString` у будь-якому середовищі; старт без нього → warning; демонстрація на двох Production-екземплярах 5080/5081 | `Program.cs` (startup log), `scripts/start-production-instance.ps1` |
| 3 | fail-safe: 429 на одному екземплярі, пауза, один warning, відновлення | локальний `FixedWindowRateLimiter` partition з тією самою quota; пауза `ReconnectPauseSeconds` (10 с), без звернень до Redis; warning лише на переході «доступний → недоступний»; info при відновленні | REG-REDIS-03 (`RedisAttempts == 1`, один warning), `redis-search-demo.ps1 -Scenario outage/recovery` |
| 4 | живий Redis + fallback тести | REG-REDIS-01/02 (живий), REG-REDIS-03 (недосяжний порт) | `Lab06RedisRateLimitTests.cs` |
| 5 | quota = наявний limiter; вбудовування; формат 429 | та сама конфігурація `RateLimit:Search:PermitLimit/WindowSeconds` (20/60 за замовчуванням; демонстрація 5/30 на обох екземплярах); policy `search` у наявному `AddRateLimiter` повертає Redis-partition; відмова — через спільний `OnRejected` (Problem Details + `Retry-After` із TTL ключа) | `Program.cs`, REG-RL-02 і REG-REDIS-01 (однаковий формат) |
| 6 | окремий вхід на 5080 і 5081 | два незалежні login (різні відбитки cookie), лічильник спільний | `redis-search-demo.ps1 -Scenario shared` |
