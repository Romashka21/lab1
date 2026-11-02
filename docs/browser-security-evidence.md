# Докази безпеки браузера (DEL-01)

Рівень: **відмінний («Відмінно»)**. Паролі, cookie/token values і export browser storage не записуються.

## Стенд і Git-стан

- ОС: Windows 11; browser: Google Chrome; API/client `http://localhost:5080`; probes `http://localhost:4173` (allowed), `http://localhost:4174` (disallowed).
- Receipt `.scaffolds/lab-05.json`: release `lab-05-start-v1`, base_commit `…`, entry_parent `…`.
- Commits: vulnerable (scaffold) `…`; seed коментаря `…`; fixed (safe DOM) `…`; CORS/CSP `…`; тег `v0.5.0` → `…`; main → `…`.
- Сеанс (Application → Cookies → http://localhost:5080), без Value: `.AspNetCore.Identity.Application`, Domain `localhost`, Path `/`, HttpOnly ✓, SameSite `Lax`, Secure ✗ (HTTP у Development).

## Гіпотеза й REG-XSS-01

Гіпотеза: значення з поля «Опис нового інциденту» (`description`) зберігається в `incidents.description`, повертається через JSON `description` у `GET /api/incidents/{id}` і передається в `#description.innerHTML` як HTML/code context. Тому, якщо текст схожий на тег з обробником події, браузер інтерпретує дані як розмітку й виконує inline handler.

REG-XSS-01:
- **Передумови:** commit (vulnerable / fixed); `dotnet run --project src/SecureLab.Api -- --reset-database`; `dotnet run --project src/SecureLab.Api`; вхід Alice через `/auth-lab.html`.
- **Вхід:** рядок із `resources/lab05-marker.txt`.
- **Кроки:** `/browser-lab.html` → нейтральна назва → marker у «Опис» → «Створити й прочитати» → у Console `document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker")`. Окремо — вікно Morgan, той самий Guid → «Прочитати»; контроль Bob.
- **Очікування (fixed):** перевірка повертає `null`; у `#description` один текстовий вузол; запиту `x` у Network немає.
- **Негативний контроль (vulnerable):** перевірка повертала `'executed'`, у `#description` був `<img>`.

| Спостереження | До fix | Після fix | Доказ |
|---|---|---|---|
| Значення в БД/API (`description`) | … | … (те саме) | Network → Response |
| DOM основного Description | … | … | Elements |
| Дія marker | … | … | Console |
| Апостроф/лапки, 5 < 7, Unicode, HTML-like | … | … | DOM |
| Довжина (≤ 4000 за ЛР 2; 3990 символів) | … | … | DOM-тест |
| Вікно Morgan: GET і перевірка; контроль Bob | … | … | Console |

Finding:
- **Актив:** сеанс користувача, що переглядає інцидент (зокрема Analyst Morgan), і дані, доступні від його імені.
- **Передумови:** локальний акаунт Reporter, контроль над полем Description.
- **Першопричина:** `browser-lab.js` `load()` передавав збережені `current.description` і `comment.text` у `innerHTML` (HTML parser) замість текстового вузла.
- **Виправлення:** helper `setPlainText()` → `createTextNode` / `replaceChildren` для обох полів.
- **Retest:** той самий marker видно як текст, дія не виконується, збережене значення не змінилось.
- **Залишковий ризик:** інші клієнти чи поля, додані пізніше; сторонній код (Scalar у Development); CSP не замінює safe sink.

## CORS і REG-CORS-01

Прогноз (до зміни policy):

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | так | так | same-origin, CORS не потрібен |
| simple GET 4173 → API | так | до policy — ні; після — так | SOP/CORS: потрібен `Access-Control-Allow-Origin: http://localhost:4173` |
| simple GET 4174 → API | так | ні | 4174 не в allowlist |
| curl/.http → API | так | не застосовується | не browser JavaScript, SOP не діє |
| preflighted 4173 → API | спершу OPTIONS; GET лише після успішного preflight | після policy — так | `X-Lab-Cors-Probe` не safelisted → preflight |
| preflighted 4174 → API | лише OPTIONS; actual GET не надсилається | ні | preflight без Allow-* |

Команди probes (з кореня проєкту, кожна у своєму терміналі):
`py -3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe` і
`py -3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe`.

Policy `Lab05BrowserProbe`: лише Development, `WithOrigins("http://localhost:4173")`, `WithMethods("GET")`, `WithHeaders("X-Lab-Cors-Probe")`, `AllowCredentials()`. 4174 — контроль. Штатний клієнт працює same-origin на 5080 і від цієї policy не залежить.

| Клієнт / простий запит | До policy | Fixed state | Status, ACAO, Console |
|---|---|---|---|
| Same-origin 5080 | … | … | … |
| Allowed 4173 | … | … | … |
| Disallowed 4174 | … | … | … |
| Direct HTTP / curl | … | … | … |

REG-CORS-01 (HTTP): `curl.exe -sS -D - -o NUL -H "Origin: http://localhost:4173" http://localhost:5080/health` → … ; те саме з 4174 → … .
Порядок middleware: `fetch("http://localhost:5080/api/incidents")` з 4173 без cookie → … .

## Добре: коментар, preflight, cookie, CSP, headers

- **Другий flow** — `docs/source-to-sink.md`, потік 2. Comment-5 до/після: …
- **Helper:** `setPlainText(element, value)` у `browser-lab.js`; викликається для `#description` і кожного `<p>` коментаря.
- **Preflight 4173/4174:** …
- **Cookie-дослід:** 4173 з входом → … ; 4174 → … ; без `AllowCredentials()` → … ; 4173 без входу → … .

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | усе з `http://localhost:5080` | `'self'` |
| script-src | `/app.js`, `/auth-lab.js`, `/browser-lab.js` | `'self'`, без `unsafe-inline` |
| style-src | `/styles.css`, `/auth-lab.css` (inline `<style>` і `style=""` винесено) | `'self'`, без `unsafe-inline` |
| connect-src | `fetch` лише до `/api/...`, `/health` того самого origin | `'self'` |
| img-src | власних зображень немає | `'self'` |
| frame-ancestors | embedding не потрібен | `'none'` (без fallback на default-src, тому явно) |
| object-src, base-uri, form-action | плагіни не потрібні; `<base>` не використовується; форми — через `fetch` | `'none'`, `'self'`, `'self'` |

| Header / control | Фактичне значення | Ризик і межа |
|---|---|---|
| X-Content-Type-Options | `nosniff` | забороняє MIME sniffing; не замінює правильний Content-Type |
| Referrer-Policy | `no-referrer` | не передає URL сторінки в Referer; клієнт не потребує referrer для навігації; не дозволяє зберігати secrets в URL |
| frame-ancestors | `'none'` | clickjacking через iframe; не замінює authorization і XSS fix |

## Відмінно

- **DOM-тест:** `tests/browser/description-dom.js`; Chrome …; vulnerable … → FAIL …; fixed … → PASS … .
- **CSP report-only → enforcement:** …
- **safe-url.js:** …

Пояснення контекстів і third-party scripts — у звіті DEL-03.
