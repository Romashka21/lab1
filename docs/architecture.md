# Карта архітектури

Це початкова карта. Під час ЛР 1 доповніть її власним трасуванням запиту,
конкретними файлами та спостереженнями з DevTools і журналу PostgreSQL.

## Компоненти

| Компонент | Розташування | Відповідальність |
|---|---|---|
| Browser client | `src/SecureLab.Api/Client/` | Надсилає HTTP-запити, безпечно показує відповідь через DOM API |
| Presentation | `Presentation/` | Описує endpoints, читає зовнішні параметри, формує HTTP-відповідь |
| Application | `Application/` | Виконує сценарій отримання списку або деталей інциденту |
| Data | `Data/` | Відображає C#-сутності на PostgreSQL через EF Core/Npgsql |
| PostgreSQL | `infra/compose.yaml` | Зберігає навчальні дані у локальному контейнері |

## Досліджений та реалізований наскрізний маршрут (severity-summary)

    кнопка "Завантажити підсумок" у Client/index.html
      → обробник кліка у Client/app.js
      → GET /api/incidents/severity-summary
      → Presentation/Endpoints/IncidentEndpoints.cs
      → Application/Incidents/IncidentQueries.cs (метод GetSeveritySummaryAsync)
      → Data/SecureLabDbContext.cs / таблиця incidents у PostgreSQL
      → IncidentSeveritySummaryResponse DTO у Presentation/Contracts/
      → JSON
      → створення <li> та textContent у Client/app.js

## Межі довіри

| Межа або перехід | Дані, що її перетинають | Чому даним ще не можна довіряти (Що не можна припускати) | Де перевіряємо або обмежуємо (Контроль) |
|---|---|---|---|
| Browser client → API | method, URL, path parameter, headers | Клієнт і запит можна змінити поза UI. Не можна припускати, що клієнт запитає лише валідний ID або статус. | Маршрутне обмеження (`:guid`), серверна валідація статусів та обробка відсутнього ресурсу (404/400). |
| API → PostgreSQL | id та умови запиту | Збережений текст автоматично не є безпечним. Право прочитати entity не означає право одержати всі поля. | Параметризація EF Core, `AsNoTracking()`, явна проєкція лише потрібних полів та DTO (без email і коментарів). |
| PostgreSQL → API → DOM | текстові значення з JSON | Текст можна інтерпретувати як HTML, що призведе до виконання шкідливого скрипта (XSS). | Використання безпечного DOM-приймача: `textContent` або `document.createTextNode` замість `innerHTML`. |

## Конфігураційні входи

- `global.json` — версія .NET SDK;
- `src/SecureLab.Api/appsettings*.json` — режим міграцій і локальний connection string;
- `infra/compose.yaml` — версія PostgreSQL, порт і локальні навчальні облікові дані;
- змінна середовища `ConnectionStrings__SecureLab` — безпечний спосіб перевизначити connection string поза репозиторієм.

## Спосіб повернення до відомого стану (Seed)

Для скидання бази даних до початкового еталонного стану використовується команда:
`dotnet run --no-build --project src/SecureLab.Api -- --reset-database`