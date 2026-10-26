# Матриця доступу ЛР04 — Incident, baseline 2-A (рівень «Відмінно»)

**Політика відмов.** Анонім → `401` (не redirect, не HTML). Ресурс, який principal **не має права бачити**
(чужий для Reporter), відповідає **так само, як неіснуючий**: `404` Problem Details `«Інцидент не знайдено»`
(відрізняється лише `traceId`). Ресурс, який principal **бачить**, але дія йому не дозволена
(Analyst → update/delete, Reporter-власник → triage, власник → delete не-New) → `403`.
Обґрунтування: Reporter не повинен навіть дізнатися, що чужий інцидент існує (зменшення disclosure);
а тому, хто ресурс бачить, явний `403` пояснює, що бракує саме права на дію.
**Administrator** не має прав, яких прямо не названо в предметному правилі 2-A (least privilege):
поводиться як автентифікований користувач без власних інцидентів.

| Дія | Рівень | Анонім | Reporter | Analyst | Administrator | Власник ресурсу має значення? | Стан реалізації |
|---|---|---:|---:|---:|---:|---:|---|
| Перегляд списку `GET /api/incidents` | добрий | deny, 401 | лише власні (чужі не повертаються) | allow — усі інциденти (для аналізу) | лише власні (немає → `[]`) | Так для Reporter/Admin | `IncidentVisibility.VisibleTo` у `IncidentQueries.GetListAsync`; тест A-05 |
| Пошук `GET /api/incidents/search` | відмінний (A-11) | deny, 401 | лише власні | allow — усі | лише власні | Так для Reporter/Admin | `VisibleTo` до сортування й `Take(50)` у `Lab02Endpoints`; тест A-11 |
| Зведення `GET /api/incidents/severity-summary` | відмінний (A-11) | deny, 401 | лише власні | allow — усі | лише власні | Так для Reporter/Admin | `VisibleTo` до `GroupBy` у `GetSeveritySummaryAsync`; тест A-11 |
| Перегляд деталей `GET /api/incidents/{id}` | достатній (entry ЛР 5) | deny, 401 | owner — allow; non-owner — deny, 404 як для неіснуючого | allow для аналізу (будь-який інцидент) | deny, 404 | Так | `IncidentOperations.Read` у `IncidentAuthorizationHandler`; тести A-02, A-03, A-03R, A-10 |
| Створення `POST /api/incidents` | успадкований baseline | deny, 401 | allow for self (owner з principal) | allow for self | allow for self | Сервер призначає власника | ЛР 3 `Lab02Endpoints`; тести ЛР 3 A-04/A-05 |
| Update content `PUT /api/incidents/{id}` (лише title, description) | добрий | deny, 401 | owner — allow, якщо статус ≠ Closed, інакше 403; non-owner — deny, 404 | deny, 403 (читання ≠ право змінювати) | deny, 404 | Так | `IncidentOperations.Update`; DTO без owner/status/role (A-08b → 400); тести A-04, A-08b, Update_AsOwner |
| Delete `DELETE /api/incidents/{id}` | добрий | deny, 401 | owner — allow лише у статусі New, інакше 403; non-owner — deny, 404 | deny, 403 | deny, 404 | Так | `IncidentOperations.Delete`; тести A-04, Delete_AsOwner |
| Зміна status: triage `POST /api/incidents/{id}/triage` | добрий | deny, 401 | deny: власник — 403 + audit; чужий — 404 + audit | allow лише New → Triaged; інший поточний статус — 409 | deny, 404 + audit | Ні (вирішує роль + поточний статус) | `IncidentOperations.Triage` + перевірка `Status == New` в endpoint; наступний статус ставить сервер; тести A-06, A-07; audit A-09 |
| Зміна severity | добрий | deny, 401 | deny (поля немає в DTO → 400) | deny (окремого transition немає) | deny | — | контракт `UpdateIncidentRequest`; тест A-08b |
| Коментар `GET /api/incident-comments/{id}` (child) | добрий | deny, 401 | allow лише для коментаря до видимого parent і не internal; інакше 404 | allow (parent видимий) | deny, 404 | Так — через parent incident | `Read` для `comment.Incident`; тест A-12 |
| Перегляд internal comment (endpoint і details-проєкція) | добрий | deny, 401 | deny — не потрапляє у відповідь (404 / відсутній у `comments`) | allow після авторизації parent incident | deny | Ні для internal rule; доступ до parent перевіряється окремо | `IncidentOperations.ReadInternalComments`; тест A-12 |
| Export/audit | відмінний, якщо flow існує | — | — | — | — | — | не застосовується: такого flow у проєкті немає |
