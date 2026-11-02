# Докази безпеки браузера (DEL-01)

Студент: Дриг Роман Андрійович, КБ-43. Сценарій 2-A. Рівень: **відмінний («Відмінно»)**; рівні накопичувальні.
Паролі, значення cookie/token і export browser storage не записуються (на скриншоті cookie стовпець Value закрито).

## Стенд і Git-стан

- ОС: Windows 11; browser: Microsoft Edge (Chromium), DevTools з `Disable cache`; .NET 10, PostgreSQL у Docker.
- API і штатний клієнт: `http://localhost:5080`; probes: `http://localhost:4173` (дозволений), `http://localhost:4174` (недозволений контроль).
- Receipt `.scaffolds/lab-05.json`: release `lab-05-start-v1`, inherits `v0.4.0`, base_commit `e0f248873297aca1ad520ef9a46280ed91eb9621`, entry_parent `e0f248873297aca1ad520ef9a46280ed91eb9621` (commit політики SDK після v0.4.0 не було — значення збігаються).
- Гілка `lab/5-browser-xss` від `v0.4.0`:

| Стан | Commit | Зміст |
|---|---|---|
| vulnerable | `4bff1cec5fed326a3e82436339867ba1df137bd5` (`4bff1ce`) | scaffold `lab-05-start-v1`: `browser-lab.html/js` з sinks `innerHTML`, probes |
| seed | `4353b68` | публічний коментар Morgan з marker, карта, evidence-шаблон, DOM-тест |
| fixed (safe DOM) | `8c66351` | `setPlainText()` для Description і comments |
| CORS/CSP | `e6f10b7f62ca967459f8a2a6452976591af94bc8` (`e6f10b7`) | Development CORS policy, CSP enforcement, nosniff, Referrer-Policy, CSS без inline |
| тег `v0.5.0` | → `e6f10b7` | анотований тег «Lab 5 browser security verified» |

- Передавання: приватний GitHub-remote; `lab/5-browser-xss` і `v0.5.0` передано (`[new tag] v0.5.0 -> v0.5.0`, гілка «up to date with origin/lab/5-browser-xss»). Стара гілка за замовчуванням `master` розійшлася з ланцюжком лабораторних ще після `v0.1.0` (commit `6cae01f` «Update report template with PDF reference»), тому `git merge --ff-only` у `master` відмовлено, і нічого не форсувалось. Fixed state передано в гілку `main`, створену з `v0.5.0` (`git branch main v0.5.0`, `git push -u origin main`); `git ls-remote --heads --tags origin`: `refs/heads/main`, `refs/heads/lab/5-browser-xss` і `refs/tags/v0.5.0^{}` → `e6f10b7f62ca967459f8a2a6452976591af94bc8` (об'єкт анотованого тегу `e8edf22`).
- Сеанс (Application → Cookies → `http://localhost:5080`), без Value: `.AspNetCore.Identity.Application`, Domain `localhost`, Path `/`, Expires `Session`, HttpOnly ✓, Secure ✗ (HTTP у Development), SameSite `Lax`.

Порти не входять до поняття site, тому cookie `localhost` з `SameSite=Lax` браузер надсилає і в запитах зі сторінок `localhost:4173/4174` (same-site, але cross-origin). Це й дає змогу провести cookie-дослід.

## Гіпотеза й REG-XSS-01

Карта: `docs/source-to-sink.md`, потоки 1 (Description) і 2 (IncidentComment.Text).

Гіпотеза: значення з поля «Опис нового інциденту» без змін іде `POST /api/incidents` → `incidents.description` → JSON `description` у `GET /api/incidents/{id}` → `browser-lab.js` `load()` → `#description.innerHTML`. Sink розбирає рядок HTML parser-ом (HTML/code context), тож тег з обробником події стає елементом DOM і inline handler виконується.

REG-XSS-01:
- **Передумови:** потрібний commit (`4bff1ce` vulnerable / `8c66351` fixed); `dotnet run --project src/SecureLab.Api -- --reset-database`; `dotnet run --project src/SecureLab.Api`; вхід Alice через `/auth-lab.html` (пароль лише в `$env:SeedUsers__Password`, введений через `Read-Host -AsSecureString`).
- **Вхід:** однорядковий marker із `resources/lab05-marker.txt`: `<img src=x onerror="document.querySelector('#lab05-marker-target').setAttribute('data-lab05-marker','executed')">` — лише ставить атрибут на власній сторінці, зовнішніх запитів і credentials не торкається.
- **Кроки:** `/browser-lab.html` → Ctrl+Shift+R → назва `XSS marker N` → marker у «Опис» → «Створити й прочитати» → Console: `document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker")`. Окремо: вікно InPrivate з Morgan → той самий Guid → «Прочитати»; контроль Bob.
- **Очікування (fixed):** `null`; у `#description` один текстовий вузол із тим самим рядком; запиту `x` у Network немає; значення в API не змінилось.
- **Негативний контроль (vulnerable):** `'executed'`; у `#description` дочірній `<img src="x">`; у Network запит `x`.

Записи: vulnerable — `XSS marker`, Guid `0e875003-4b7d-4297-ba69-ae2719cc79c8`; fixed — `XSS marker 3`, Guid `4d8e8fb1-f9bc-41a9-a31c-c07609ec65d6` (той самий marker; новий запис, бо reset між станами видаляє створені інциденти).

| Спостереження | До fix (`4bff1ce`) | Після fix (`8c66351`) | Доказ |
|---|---|---|---|
| Значення в БД/API (`description`) | `"<img src=x onerror=\"document.querySelector('#lab…"` | те саме значення (`\"` — запис JSON, а не зміна) | Network → Preview |
| DOM основного Description | `<div id="description">` містить елемент `<img>`; на сторінці «бита» картинка | `#description` містить рядок у лапках (text node), `<img>` немає | Elements |
| Дія marker | `'executed'`; у Network запит `x` | `null`; запиту `x` немає | Console / Network |
| Апостроф/лапки, 5 < 7, Unicode | `Користувач O'Brien написав "терміново"`, `5 < 7 і 9 > 3`, `Київ — Ω` показано правильно | ті самі рядки правильні (DOM-тест, positive 1) | сторінка, DOM-тест |
| HTML-like рядок `<b>жирний</b> текст` | **жирний** — у DOM створено `<b>` (дефект видно навіть без marker) | показано буквально `<b>жирний</b> текст`, елемента `<b>` немає | сторінка + Elements |
| Довжина (≤ 4000 за ЛР 2) | `Тест 5`: довгий рядок «A» показано цілим | DOM-тест: `"А".repeat(3990)` — текст збігається з API, без дочірніх елементів | сторінка, DOM-тест |
| Вікно Morgan; контроль Bob | — (окремо до fix не фіксувалось) | Morgan (InPrivate) бачить marker як текст, `null`; Bob → `GET: 404` (авторизація ЛР 4 не змінилась) | сторінка + Console |

Finding:
- **Актив:** сеанс користувача, що переглядає інцидент (насамперед Analyst Morgan, який читає інциденти всіх заявників), і дані та дії, доступні від його імені через same-origin `fetch`.
- **Передумови:** локальний акаунт Reporter і контроль над полем Description (або текстом коментаря).
- **Першопричина:** `browser-lab.js` `load()` передавав збережені `current.description` і `comment.text` у `innerHTML`, тобто в HTML parser, замість текстового вузла.
- **Виправлення (safe DOM diff):** helper `setPlainText(element, value)` = `element.replaceChildren(document.createTextNode(value ?? ""))`; викликається для `#description` і для кожного `<p>` коментаря; `#comments.replaceChildren(...paragraphs)`. Без blacklist/regex і без зміни даних.
- **Retest:** той самий marker видно як текст, дія не виконується, значення в API не змінилось; позитивні рядки правильні.
- **Залишковий ризик:** інші клієнти або поля, додані пізніше з `innerHTML`/`insertAdjacentHTML`; сторонній код (Scalar на `/scalar` лише в Development, без CSP); CSP — додатковий шар і не замінює safe sink.

## CORS і REG-CORS-01

Прогноз (до зміни policy):

| Сценарій | Чи доходить request до API? | Чи може JavaScript прочитати response? | Чому |
|---|---|---|---|
| same-origin 5080 → API | так | так | same-origin, CORS не потрібен |
| simple GET 4173 → API | так | до policy — ні; після — так | потрібен `Access-Control-Allow-Origin: http://localhost:4173` |
| simple GET 4174 → API | так | ні | 4174 не в allowlist |
| curl → API | так | не застосовується | не browser JavaScript, SOP не діє |
| preflighted 4173 → API | спершу OPTIONS; GET лише після успішного preflight | після policy — так | `X-Lab-Cors-Probe` не safelisted → preflight |
| preflighted 4174 → API | лише OPTIONS; actual GET не надсилається | ні | preflight без Allow-* |

Команди probes (з кореня проєкту, кожна у своєму терміналі):
`py -3 -m http.server 4173 --bind localhost --directory demonstrations/cors-probe` і
`py -3 -m http.server 4174 --bind localhost --directory demonstrations/cors-probe`.

Policy `Lab05BrowserProbe` (`Program.cs`): лише `IsDevelopment()`, `WithOrigins("http://localhost:4173")`, `WithMethods("GET")`, `WithHeaders("X-Lab-Cors-Probe")`, `AllowCredentials()`; `app.UseRouting(); app.UseCors("Lab05BrowserProbe");` — до `UseAuthentication/UseAuthorization`. 4174 — контроль. Штатний клієнт працює same-origin на 5080 і від policy не залежить.

| Клієнт / запит | До policy (`8c66351`) | Fixed state (`e6f10b7`) | Status, ACAO, Console |
|---|---|---|---|
| Same-origin 5080 | `browser-lab` читає `GET /api/incidents/{id}` → 200 | так само 200 | CORS не застосовується |
| Allowed 4173, кнопка GET `/api/incidents` (credentials: include) | Network: `incidents` **200** (запит дійшов), JS: «Браузер не надав response…»; Console: `No 'Access-Control-Allow-Origin' header` | `200: [{"id":…,"title":"DOM-REG …"}…]` — список Alice прочитано | ACAO `http://localhost:4173`, ACAC `true` |
| Allowed 4173, `fetch("/health")` без credentials | — | `{status: 200, body: '{"status":"ready"}'}` | ACAO 4173 |
| Disallowed 4174, кнопка GET | — | Console: `No 'Access-Control-Allow-Origin' header`; `net::ERR_FAILED` — запит дійшов до API, відповідь браузер не віддав | ACAO відсутній |
| Direct HTTP / curl | — | `HTTP/1.1 200 OK` і тіло `{"status":"ready"}` для будь-якого Origin | ACAO лише для 4173 |

REG-CORS-01 (HTTP, PowerShell):
```
curl.exe -sS -D - -o NUL -H "Origin: http://localhost:4173" "http://localhost:5080/health"
  → 200; Access-Control-Allow-Credentials: true; Access-Control-Allow-Origin: http://localhost:4173
curl.exe -sS -D - -o NUL -H "Origin: http://localhost:4174" "http://localhost:5080/health"
  → 200; Access-Control-Allow-* відсутні
curl.exe -i -H "Origin: http://localhost:4174" "http://localhost:5080/health"
  → 200 і тіло {"status":"ready"} — curl не застосовує SOP/CORS
```
В усіх відповідях: `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, CSP-заголовок.

Порядок middleware: InPrivate-вікно без cookie → `http://localhost:4173` → GET `/api/incidents` → `401: {"title":"Unauthorized","status":401,…}` прочитано JavaScript-ом. Отже CORS headers додаються і до 401 (UseCors стоїть до authentication), а authorization все одно відмовила.

## Добре: коментар, helper, preflight, cookie, CSP, headers

- **Другий flow** — `docs/source-to-sink.md`, потік 2. Seed-коментар `30000000-0000-0000-0000-000000000005` (автор Morgan, `IsInternal = false`) до інциденту Alice `20000000-0000-0000-0000-000000000001` «Підозрілий лист із вкладенням»; `comments` = 2 публічні (internal-коментар Alice не бачить — правило ЛР 4).
  - До fix: у `#comments` другий `<p>` містить `<img src="x" onerror=…>`, у span `data-lab05-marker="executed"`.
  - Після fix: другий `<p>` містить рядок у лапках; перевірка → `null`.
- **Helper:** `setPlainText(element, value)` у `browser-lab.js`; один helper для `#description` і кожного коментаря.
- **Preflight** (`fetch("http://localhost:5080/health", { headers: { "X-Lab-Cors-Probe": "stage-3" } })`):
  - 4173 до policy: `Response to preflight request doesn't pass access control check: No 'Access-Control-Allow-Origin'`; `TypeError: Failed to fetch`; actual GET не надіслано.
  - 4173 після policy: `{status: 200, body: '{"status":"ready"}'}` — OPTIONS дозволив `GET` і `x-lab-cors-probe`, після нього пройшов GET.
  - 4174 після policy: той самий blocked preflight; actual GET не надіслано.
- **Cookie-дослід:**
  - 4173 з входом Alice, `AllowCredentials()` → 200 і список інцидентів Alice.
  - 4173 без `AllowCredentials()` (рядок тимчасово закоментовано) → `The value of the 'Access-Control-Allow-Credentials' header in the response is '' which must be 'true' when the request's credentials mode is 'include'`; Network: 200 — запит із cookie дійшов, браузер не віддав відповідь. Після досліду рядок повернуто.
  - 4174 → блок за ACAO.
  - 4173 без входу (InPrivate) → 401 прочитано.
  - Кінцевий `AllowCredentials()` — лише в Development policy для одного exact origin 4173.

| Директива CSP | Фактичні ресурси застосунку | Обране джерело / причина |
|---|---|---|
| default-src | усе з `http://localhost:5080` | `'self'` |
| script-src | `/app.js`, `/auth-lab.js`, `/browser-lab.js` | `'self'`, без `unsafe-inline` |
| style-src | `/styles.css`, `/auth-lab.css` (inline `<style>` і `style=""` винесено в CSS) | `'self'`, без `unsafe-inline` |
| connect-src | `fetch` лише до `/api/...`, `/health` того самого origin | `'self'` |
| img-src | власних зображень немає | `'self'` |
| frame-ancestors | вбудовування не потрібне | `'none'` (не успадковується від default-src, тому явно) |
| object-src, base-uri, form-action | плагіни не потрібні; `<base>` не використовується; форми надсилаються через `fetch` | `'none'`, `'self'`, `'self'` |

Місце зміни: middleware `app.Use(...)` у `Program.cs` до `UseRouting/UseCors`; ім'я заголовка — константа `CspHeaderName`; виняток лише для `/scalar` у Development.

| Header / control | Фактичне значення | Ризик і межа захисту |
|---|---|---|
| X-Content-Type-Options | `nosniff` | браузер не вгадує MIME (відповідь `text/plain`/JSON не виконається як script/style); не замінює правильний Content-Type |
| Referrer-Policy | `no-referrer` | URL сторінки (з Guid інциденту в адресі чи query) не передається третім сторонам у `Referer`; не дозволяє зберігати secrets в URL |
| frame-ancestors | `'none'` | clickjacking: сторінку не можна вбудувати в iframe чужого origin; не замінює authorization і XSS fix |

## Відмінно

- **DOM-тест:** файл `tests/browser/description-dom.js`, запуск у Console сторінки `/browser-lab.html` (Microsoft Edge) з Guid fixture у полі `#incident-id`.
  - Vulnerable `browser-lab.js` з `4bff1ce` (тимчасово `git checkout 4bff1ce -- src/SecureLab.Api/Client/browser-lab.js`, без commit; сервер — стан `v0.5.0` з CSP enforcement), fixture `XSS marker FAIL` (Guid `648b6c17-69aa-41d1-8322-…`) → **FAIL: fixture: description text equals API value** — у `#description` створено `<img>`, тож текст DOM не дорівнює значенню API. Водночас Console: «Executing inline event handler violates … script-src 'self' … The action has been blocked» — CSP заблокувала виконання marker, але дефект sink лишився, і тест його ловить. Після запуску файл повернуто: `git checkout HEAD -- src/SecureLab.Api/Client/browser-lab.js`.
  - Fixed `8c66351` → **PASS: 31 checks — Description і comments відображаються як текст**: fixture `XSS marker 3`; seed-інцидент `…0001` (2 коментарі, у кожному `<p>` text node без елементів, marker-коментар присутній); повторний `load()` не дублює `<p>` і лишає один text node в `#description`; marker не виконався (500 мс); positive 1 (O'Brien, лапки, `5 < 7 і 9 > 3`, `<b>жирний</b> текст`, `Київ — Ω`) і positive 2 (`"А".repeat(3990)`): POST 201 → GET 200 → текст = значенню API, значення не змінено.
- **CSP report-only → enforcement:**
  - Report-only (`Content-Security-Policy-Report-Only`): заголовок на `browser-lab.html`; `auth-lab.html:7` — порушення `style-src 'self'` (inline `<style>`), `index.html` (рядки 49 і 52) — 2 порушення (атрибути `style`), стилі застосовано; `new Image().src = "http://localhost:4173/x.png"` → «violates … img-src 'self'. The policy is report-only…».
  - Виправлення: стилі `auth-lab.html` → `auth-lab.css`, атрибути `style` в `index.html` → класи `summary-section`/`summary-status` у `styles.css`; після Ctrl+Shift+R на обох сторінках порушень немає.
  - Enforcement (`Content-Security-Policy`): заголовок на `browser-lab.html`; `new Image()` до 4173 → «… img-src 'self'. The action has been blocked.»; основний flow працює: читання `XSS marker 3` (`null`), створення `CSP check` (Guid `ba1624b4-1d2f-4b1b-a6cd-…`), без CSP-помилок.
  - frame-ancestors: з `http://localhost:4173` iframe на `/browser-lab.html` → «Framing 'http://localhost:5080/' violates … "frame-ancestors 'none'". The request has been blocked.»
  - `/scalar` (Development): CSP відсутній, `nosniff` і `no-referrer` є — навмисний виняток для стороннього UI.
- **safe-url.js** (`safeHttpUrl(value, base)`): `https://example.com/a` → той самий URL; `/incidents/1` → `http://localhost:5080/incidents/1`; `javascript:alert(1)` → `null`; ` JaVaScRiPt:alert(1)` → `null`; `http://[bad` → `null`. URL-контекст потребує allowlist схем після парсингу через `URL`, а не textContent.
- **Регресія сервера:** `dotnet test` до змін — 53/53; фінально після `--reset-database` — 53/53. Без reset A11 (ЛР 4) падав: DOM-тест створив інцидент Alice з `O'Brien`, а A11 очікує, що в Alice такого немає. Висновок: тести залежать від seed-стану, reset — обов'язкова передумова.

Пояснення контекстів text/attribute/URL/JavaScript і ризику third-party scripts — у звіті DEL-03.
