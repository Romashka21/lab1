# Звіт WEB ЛР 5

Автор: Дриг Роман Андрійович, КБ-43. Спільний сценарій 2-A «Трекер інцидентів». Рівень: **«Відмінно»** (накопичувально: Задовільно + Добре + Відмінно). ОС/browser: Windows 11, Microsoft Edge (Chromium); .NET 10, PostgreSQL у Docker; API `http://localhost:5080`, probes `http://localhost:4173` / `http://localhost:4174`.

## Для всіх рівнів

**DEL-01:** `docs/source-to-sink.md` (потоки Description і IncidentComment.Text, інвентаризація sinks) і `docs/browser-security-evidence.md` (REG-XSS-01, REG-CORS-01, CSP/headers, DOM-тест).

Коротко до → причина → fix → retest → залишковий ризик:
- **До:** marker, збережений в Description (і в seed-коментарі Morgan), при перегляді створював `<img>` у `#description`/`#comments` і ставив `data-lab05-marker="executed"`; навіть `<b>жирний</b> текст` ставав жирним.
- **Причина:** у `browser-lab.js` `load()` збережені значення передавались у `innerHTML` (HTML parser) — DOM-based sink для stored даних.
- **Fix:** один helper `setPlainText()` (`replaceChildren(createTextNode(...))`) для обох полів; дані в БД/API не змінюються, backend validation не «чистить» HTML.
- **Retest:** той самий marker видно як текст, перевірка → `null`, у Network немає `x`; складні позитивні рядки правильні; Morgan бачить текст, Bob → 404; DOM-тест PASS (31 перевірка).
- **Залишковий ризик:** нові клієнти/поля з `innerHTML`; сторонній UI Scalar у Development без CSP; CSP — лише другий шар.

**DEL-02:**
- receipt: release `lab-05-start-v1`, base_commit = entry_parent = `e0f248873297aca1ad520ef9a46280ed91eb9621` (`v0.4.0`);
- vulnerable `4bff1cec5fed326a3e82436339867ba1df137bd5`; seed `4353b68`; fixed `8c66351`; CORS/CSP `e6f10b7f62ca967459f8a2a6452976591af94bc8`;
- тег `v0.5.0` → `e6f10b7`;
- приватний GitHub-remote: передано `lab/5-browser-xss`, `v0.5.0` і `main` (створено з `v0.5.0`, бо стара `master` розійшлася з ланцюжком ЛР після `v0.1.0` і `--ff-only` у неї неможливий; нічого не форсувалось); `git ls-remote --heads --tags origin`: `main`, `lab/5-browser-xss` і `v0.5.0^{}` → `e6f10b7`.

**DEL-03:** відповіді нижче.

## Контрольні питання

1. **Чому value з БД може залишатися недовіреним?** У БД лежить те, що ввів користувач. Запис через API з авторизацією підтверджує *хто* записав, а не *що* це безпечний HTML. У нашому flow marker пройшов validation ЛР 2 (довжина, required) і зберігся символ у символ — довіра визначається походженням даних і контекстом виводу, а не місцем зберігання.
2. **Source, transformation і sink у моєму flow.** Source — `<textarea name="description">` (і seed `IncidentComment.Text`); transformations — JSON у `POST`, validation/`Trim()` у `Lab02Endpoints`, запис у `incidents.description`, JSON-серіалізація у `GET /api/incidents/{id}`, `response.json()`; sink — `#description.innerHTML` / `paragraph.innerHTML` (HTML/code context). Після fix sink — text node.
3. **Stored vs reflected vs DOM-based XSS.** Stored — payload зберігається на сервері й виконується в кожного, хто відкриє запис (наш випадок; жертва — Morgan). Reflected — payload приходить у запиті (query/form) і одразу повертається у відповіді. DOM-based — небезпечне перетворення відбувається в клієнтському JS (source → sink у браузері). У нас stored-дані реалізуються через DOM sink: сервер повертав чистий JSON, HTML робив клієнт.
4. **Чому блокування `<script>` не усуває XSS?** HTML має багато інших шляхів виконання: обробники подій (`onerror`, `onload`), `javascript:` URL, `srcdoc`, SVG тощо. Наш marker не містить `<script>` взагалі — `<img src=x onerror=…>`. До того ж `<script>`, вставлений через `innerHTML`, і так не виконується, а `onerror` — виконується.
5. **textContent чи sanitizer?** `textContent`/`createTextNode` — коли значення має бути простим текстом (наш контракт 2-A: formatted HTML заборонено). Sanitizer (перевірена бібліотека з allowlist, напр. DOMPurify) — лише коли продукт свідомо дозволяє обмежений HTML (rich text), і тоді ще потрібна CSP.
6. **Чому sanitizer не пишуть regular expression?** HTML не є регулярною мовою: браузер виправляє помилки, декодує сутності, змінює регістр, розбирає вкладені й незакриті теги, контексти атрибутів/URL/SVG. Regex-blacklist обходять варіантами (` JaVaScRiPt:`, `<img/src=x onerror=…>`, сутності). Безпечне рішення — не парсити HTML взагалі або використати парсер браузера з allowlist.
7. **З яких трьох компонентів складається origin?** Scheme + host + port. `http://localhost:4173` і `http://localhost:5080` — різні origins (різні порти), хоча site той самий.
8. **Що browser надсилає в preflight і хто його ініціює?** Браузер (не скрипт і не сервер) автоматично надсилає `OPTIONS` з `Origin`, `Access-Control-Request-Method` (у нас `GET`) і `Access-Control-Request-Headers` (`x-lab-cors-probe`), коли actual request не є «простим» (тут — через нестандартний заголовок). Actual GET надсилається лише якщо відповідь preflight дозволяє origin, метод і заголовок (4173 після policy), інакше не надсилається (4174).
9. **Хто оголошує і хто застосовує CORS?** Оголошує сервер (API) заголовками `Access-Control-Allow-*`, які формує policy `Lab05BrowserProbe`. Застосовує браузер: він порівнює ці заголовки з origin сторінки і вирішує, чи віддати відповідь скрипту / чи надсилати actual request. API запит обробляє в будь-якому разі (у Network 4174 видно 200).
10. **Чому curl читає response, а script отримує CORS error?** SOP і CORS — правила браузера для JavaScript чужого origin. curl не є браузером, не має origin сторінки і не застосовує CORS: `curl.exe -i -H "Origin: http://localhost:4174"` отримав 200 і `{"status":"ready"}`. Тому CORS не захищає API від прямих клієнтів.
11. **Чому CORS не є authorization і не замінює CSRF-захист?** CORS лише послаблює SOP для читання відповіді конкретним origin-ом; рішення про доступ ухвалює authentication/authorization (у InPrivate з 4173 CORS пропустив, але API повернув 401; Bob отримує 404). CSRF — це надсилання запиту від імені жертви з її cookie; запит доходить до сервера незалежно від CORS (простий POST форми взагалі без preflight), CORS блокує лише читання відповіді. Від CSRF захищають SameSite, antiforgery-токени, перевірка Origin.
12. **Чому wildcard не поєднують із credentials?** `*` + cookie дозволили б будь-якому сайту читати дані від імені залогіненого користувача. Тому специфікація забороняє `Access-Control-Allow-Origin: *` разом з `Access-Control-Allow-Credentials: true`; потрібен exact origin. Ризикований обхід — віддзеркалювати будь-який `Origin`. У нас — один exact origin 4173, лише Development.
13. **Межа CSP і чому вона не замінює safe DOM.** CSP обмежує, звідки браузер завантажує скрипти/стилі/зображення/фрейми і чи виконувати inline-код. Вона не виправляє sink: розмітка все одно потрапляє в DOM (HTML-injection, підміна інтерфейсу), політика може бути послаблена (`unsafe-inline`), а дозволені same-origin скрипти й гаджети працюють. Тому основний захист — `setPlainText`, CSP — defence in depth.
14. **Ризики, які зменшують nosniff, Referrer-Policy і frame-ancestors.** `nosniff` — браузер не вгадує тип відповіді, тож JSON/текст не виконається як script чи style. `Referrer-Policy: no-referrer` — адреси сторінок (Guid інцидентів, параметри) не витікають іншим сайтам у `Referer`. `frame-ancestors 'none'` — сторінку не можна вбудувати в iframe чужого сайту (clickjacking); перевірено з 4173 — фрейм заблоковано.

## Додатково для Добре та Відмінно

- **IncidentComment.Text:** seed-коментар `30000000-…0005` (Morgan, public) до інциденту Alice `20000000-…0001`; до fix — `<img>` у `#comments` і `executed`, після — текст і `null`.
- **Safe helper:** `setPlainText(element, value)` для `#description` і кожного `<p>` коментаря; `#comments.replaceChildren(...)` — повторний render без дублювання.
- **Preflight:** 4173 до policy — blocked, actual GET не надіслано; після — OPTIONS дозволив `GET` + `x-lab-cors-probe`, GET 200; 4174 — blocked.
- **Cookie-дослід:** 4173 + `AllowCredentials()` → 200 і список Alice; без `AllowCredentials()` → помилка «'Access-Control-Allow-Credentials' … is '' which must be 'true'»; 4174 → немає ACAO; 4173 без входу → 401 прочитано.
- **CSP enforcement і headers:** `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'`; `nosniff`; `no-referrer`; flow працює без порушень.

**Обґрунтування policy:** штатний клієнт — same-origin, тому CORS у production не потрібен узагалі. Навчальна policy: лише `IsDevelopment()`, один exact origin (не `*`, не віддзеркалення), лише `GET`, лише один заголовок. `AllowCredentials()` лишено свідомо, бо дослід показав його наслідок: дозволений origin читає дані користувача, тому allowlist має містити тільки довірений origin. `UseCors` стоїть до authentication, щоб і 401/403 мали CORS headers (клієнт бачить причину), а не маскувались під CORS error.

**Review XSS / CORS / CSRF / authorization:**
- **XSS** — чужий код виконується *в нашому origin*: має доступ до DOM, same-origin `fetch` з cookie; SOP/CORS його не зупиняють. Лікується правильним sink, CSP — додатково.
- **CORS** — контрольоване *послаблення* SOP для читання відповідей іншим origin-ом. Не захищає сервер і не дає прав.
- **CSRF** — запит від імені жертви з іншого сайту; ризик стосується state-changing запитів з cookie. Захист — SameSite, antiforgery-токен, перевірка Origin (CSRF-токени в проєкті ще не реалізовано: SameSite=Lax — часткова мітигація).
- **Authorization** — серверне рішення «суб'єкт + дія + ресурс» (ЛР 4). Не залежить від CORS; XSS обходить її, бо діє від імені вже авторизованого користувача.

## Додатково для Відмінно

- **DOM-тест:** `tests/browser/description-dom.js`, Console `/browser-lab.html`, Microsoft Edge. Vulnerable `browser-lab.js` (`4bff1ce`) → `FAIL: fixture: description text equals API value` (у `#description` з'явився `<img>`; виконання marker при цьому заблокувала CSP enforcement — defence in depth працює, але дефект sink лишився і тест його ловить); fixed `8c66351` → `PASS: 31 checks`.
- **Report-only → enforcement:** report-only показав 3 inline-style порушення (`auth-lab.html:7`, `index.html` ×2) і `img-src` для 4173 без блокування; стилі перенесено в CSS (без `unsafe-inline`); enforcement блокує зображення 4173 і framing, flow працює.
- **Comments і повторний render:** кожен `<p>` має лише text node; повторний `load()` не дублює коментарі й лишає один text node в `#description`.
- **Контексти виведення:**
  - Text (вміст елемента) — `textContent`/`createTextNode`.
  - Attribute — лише `setAttribute` для безпечних атрибутів, ніколи `on*` чи `style` з даних; значення в лапках через DOM API, а не конкатенація HTML.
  - URL (`href`/`src`) — парсинг через `URL` і allowlist `http:`/`https:` (`safeHttpUrl`: `javascript:` у будь-якому регістрі й з пробілом → `null`), бо `textContent` не захищає від `javascript:`.
  - JavaScript-контекст — дані ніколи не потрапляють у `eval`, `new Function`, `setTimeout(string)` чи inline-скрипт; лише як JSON-дані.
- **Ризик third-party scripts:** сторонній скрипт, підключений на сторінку, виконується з тими самими правами, що й наш (DOM, same-origin `fetch`, cookie без HttpOnly), і CSP `'self'` його не обмежить, якщо його явно дозволити. У проєкті сторонній UI — лише Scalar на `/scalar`, тільки в Development, з навмисним винятком CSP; у production його не має бути. Для CDN-скриптів потрібні точні джерела в CSP і Subresource Integrity.

## Зміни в коді по файлах

| Файл | Що зроблено | Commit |
|---|---|---|
| `src/SecureLab.Api/Client/browser-lab.html`, `browser-lab.js`, `demonstrations/cors-probe/index.html`, `probe.js`, `.scaffolds/lab-05.json` | видано scaffold `lab-05-start-v1` (вразливий стан), власноруч не писались | `4bff1ce` |
| `src/SecureLab.Api/Data/DbSeeder.cs` | **змінено**: константа `Lab05Marker` і публічний коментар Morgan | `4353b68` |
| `src/SecureLab.Api/Client/browser-lab.js` | **змінено**: helper `setPlainText`, заміна двох `innerHTML` | `8c66351` |
| `src/SecureLab.Api/Program.cs` | **змінено**: CORS policy, CSP і headers у middleware, `UseRouting` + `UseCors` | `e6f10b7` |
| `src/SecureLab.Api/Client/auth-lab.html` | **змінено**: inline `<style>` → `<link>` | `e6f10b7` |
| `src/SecureLab.Api/Client/auth-lab.css` | **новий** файл зі стилями з `auth-lab.html` | `e6f10b7` |
| `src/SecureLab.Api/Client/index.html` | **змінено**: атрибути `style` → класи | `e6f10b7` |
| `src/SecureLab.Api/Client/styles.css` | **змінено**: класи `.summary-section`, `.summary-status` | `e6f10b7` |
| `tests/browser/description-dom.js` | **новий** DOM-тест (Console) | `4353b68` |
| `docs/source-to-sink.md`, `docs/browser-security-evidence.md`, `docs/report-lab-05.md` | **нові** документи | `4353b68` / evidence-commit |

### 1. `DbSeeder.cs` — marker у коментарі

Перед викликом `dbContext.IncidentComments.AddRange(` додано константу:

```csharp
// ЛР 5: канонічний harmless marker для другого sink — IncidentComment.Text.
const string Lab05Marker =
    "<img src=x onerror=\""
    + "document.querySelector('#lab05-marker-target')"
    + ".setAttribute('data-lab05-marker','executed')\">";
```

В `AddRange(...)` після останнього коментаря (internal-коментар Morgan) додано ще один:

```csharp
// ЛР 5: публічний коментар Morgan із marker (comment-5).
new IncidentComment
{
    Id = Guid.Parse("30000000-0000-0000-0000-000000000005"),
    Incident = aliceIncident,
    Author = morgan,
    Text = Lab05Marker,
    IsInternal = false,
    CreatedAtUtc = new DateTimeOffset(2026, 8, 1, 9, 35, 0, TimeSpan.Zero)
}
```

Рядок розбито на частини, щоб уникнути проблем з лапками в C#; `IsInternal = false`, щоб коментар бачила й Alice (власниця інциденту), а не лише Analyst.

### 2. `browser-lab.js` — safe DOM

Було (функція `load()`):

```js
document.querySelector("#description").innerHTML = current.description;
document.querySelector("#comments").replaceChildren();
for (const comment of current.comments ?? []) {
  const paragraph = document.createElement("p");
  paragraph.innerHTML = comment.text;
  document.querySelector("#comments").append(paragraph);
}
```

Стало — новий helper над `async function load()`:

```js
// ЛР 5: єдиний safe render helper для Description і IncidentComment.Text.
function setPlainText(element, value) {
  element.replaceChildren(document.createTextNode(value ?? ""));
  return element;
}
```

і в `load()` замість рядків вище:

```js
setPlainText(document.querySelector("#description"), current.description);
const paragraphs = (current.comments ?? []).map(comment =>
  setPlainText(document.createElement("p"), comment.text));
document.querySelector("#comments").replaceChildren(...paragraphs);
```

Решта файлу (`#title.textContent`, обробник форми) не змінювалась.

### 3. `Program.cs` — CORS, CSP, headers

(а) Після реєстрації сервісів (перед `builder.Services.Configure<RouteHandlerOptions>`):

```csharp
// ЛР 5: навчальна CORS policy лише для Development — один exact origin 4173.
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddCors(options =>
    {
        options.AddPolicy("Lab05BrowserProbe", policy =>
        {
            policy.WithOrigins("http://localhost:4173")
                  .WithMethods("GET")
                  .WithHeaders("X-Lab-Cors-Probe")
                  .AllowCredentials();
        });
    });
}
```

(б) Перед наявним `app.Use(async (context, next) => { ... nosniff ... })` — константи, а всередині middleware — встановлення CSP:

```csharp
// ЛР 5: спершу Report-Only, після перевірки — "Content-Security-Policy".
const string CspHeaderName = "Content-Security-Policy-Report-Only";
const string Csp =
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; "
    + "object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'";

app.Use(async (context, next) =>
{
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers.Append("Referrer-Policy", "no-referrer");

    // Виняток лише для Development-довідника Scalar.
    var isDevelopmentApiReference =
        app.Environment.IsDevelopment()
        && context.Request.Path.StartsWithSegments("/scalar");
    if (!isDevelopmentApiReference)
    {
        context.Response.Headers[CspHeaderName] = Csp;
    }

    await next(context);
});
```

Для enforcement змінено один рядок: `const string CspHeaderName = "Content-Security-Policy";`.

(в) Перед `app.UseAuthentication();`:

```csharp
// ЛР 5: CORS до authentication/authorization — CORS headers є й на 401/403.
app.UseRouting();
if (app.Environment.IsDevelopment())
{
    app.UseCors("Lab05BrowserProbe");
}
```

### 4. `auth-lab.html` і новий `auth-lab.css`

У `auth-lab.html` блок `<style> ... </style>` видалено, у `<head>` додано:

```html
<link rel="stylesheet" href="auth-lab.css">
```

Новий файл `src/SecureLab.Api/Client/auth-lab.css` (ті самі правила, що були в `<style>`):

```css
/* ЛР 5: стилі винесено з inline <style>, щоб CSP style-src 'self' не потребувала unsafe-inline. */
body { font-family: system-ui, sans-serif; max-width: 46rem; margin: 1.5rem auto; padding: 0 1rem; }
fieldset { margin: 1rem 0; }
label { display: block; margin: .3rem 0; }
input, select, textarea { width: 100%; box-sizing: border-box; }
button { margin: .4rem .4rem .4rem 0; }
pre { background: #f4f4f4; padding: .6rem; white-space: pre-wrap; }
```

### 5. `index.html` і `styles.css`

В `index.html` (рядки 49 і 52, про них звітувала CSP) атрибути `style="..."` замінено класами:

```html
<section id="summary-section" class="summary-section">
...
<span id="summary-status" class="summary-status"></span>
```

У кінець `styles.css` додано ті самі властивості:

```css
.summary-section {
  margin-top: 2rem;
  padding: 1rem;
  border-top: 1px solid #ccc;
}

.summary-status {
  margin-left: 10px;
  color: #555;
}
```

### 6. Новий `tests/browser/description-dom.js`

Тест фактичного DOM, запускається в Console сторінки `/browser-lab.html` після Ctrl+Shift+R, з Guid fixture у полі. Логіка:
- `check(condition, message)` — кидає `FAIL: …` або додає `ok - …`;
- `renderAndCheck(id, label)` — `fetch` запису, `load()`, порівнює `#description.textContent` і кожен `<p>` з JSON, вимагає `childElementCount === 0`;
- fixture (власний запис із marker), seed-інцидент `…0001` (коментар з marker), подвійний `load()` — без дублювання, `pause(500)` → marker `null`;
- два позитивні рядки через `POST /api/incidents` → 201 → render → значення не змінено.

Повний текст — у додатку Word-звіту і у файлі в репозиторії.

### 7. Без змін у файлах

`safeHttpUrl` перевірено в Console (контекст URL, у клієнті поки немає посилань із даних). CORS-дослід без `AllowCredentials()` — тимчасова зміна, повернута до commit.

## Декларація використання ШІ

Використовував: Claude (Anthropic).
- **Що отримав:** розбір методички й покроковий план із переліком скриншотів; чернетки `DbSeeder.cs` (seed-коментар), helper `setPlainText` у `browser-lab.js`, CORS/CSP-фрагменти `Program.cs`, перенесення inline-стилів у CSS, розширений DOM-тест `description-dom.js`; чернетки карти, evidence і цього звіту.
- **Що зробив власноруч:** виконав усі кроки на власному стенді, окремі commit для vulnerable/seed/fixed/CORS-CSP; створював marker-інциденти й позитивні рядки; тимчасово вимикав `AllowCredentials()` для досліду і повертав; переходив report-only → enforcement; вирішив не форсувати merge у `master`, що розійшовся.
- **Фактично виконані перевірки:** browser-перевірки (Elements/Console/Network) до і після, вікна Morgan/Bob, DOM-тест PASS, CORS з 4173/4174 і curl, CSP в обох режимах, `dotnet test` 53/53 (до і після, з reset), `git diff` vulnerable..fixed.
- **Висновки, які можу пояснити:** чому `innerHTML` небезпечний і `createTextNode` — ні; що CORS застосовує браузер, а не сервер, і що він не є authorization; навіщо preflight; чому CSP не замінює safe sink; чому тести залежать від seed-стану.

Секрети, cookie, паролі й повний чат у звіт не вставлялись.

## Межі перевірки

- Перевірено фактично: локальний стенд (loopback), штучні seed-дані, Microsoft Edge; Description і IncidentComment.Text у `browser-lab`; CORS з двох probe-origin і curl; CSP/headers на сторінках `browser-lab`, `auth-lab`, `index`, `/scalar`; 53 серверні тести.
- Поза стендом: інші браузери (Firefox/Safari), production-конфігурація (HTTPS, `Secure` cookie, HSTS), CSRF-токени (ЛР 6), автоматизований browser-тест у CI (DOM-тест запускається вручну в Console), створення коментарів через API (endpoint відсутній — comment-flow перевірено на seed).
- Нереальні PASS не записувались: перший запуск DOM-тесту на vulnerable зупинився на 404 (fixture видалено reset-ом) і не врахований; FAIL отримано окремим запуском з vulnerable `browser-lab.js` поверх сервера `v0.5.0`, тому marker там заблокувала CSP, а не safe sink.
