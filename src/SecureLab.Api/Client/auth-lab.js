// ЛР 3: власний браузерний сценарій register -> login -> profile -> create -> logout.
// Правила: лише same-origin fetch; текст у DOM тільки через textContent; пароль очищається після спроби;
// ні логін, ні профіль, ні cookie не зберігаються в localStorage/sessionStorage і не друкуються в Console.

const $ = selector => document.querySelector(selector);
const result = $("#result");
const profileBox = $("#profile");
const incidentBox = $("#incident-result");

// Лише свій origin; cookie надсилає браузер (HttpOnly, JavaScript її не бачить).
function apiFetch(path, options = {}) {
  const url = new URL(path, location.origin);
  if (url.origin !== location.origin) throw new Error("Потрібна адреса цього застосунку.");
  return fetch(url, { ...options, credentials: "same-origin" });
}

function jsonBody(data) {
  return { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(data) };
}

function isJson(response) {
  return (response.headers.get("Content-Type") || "").includes("json");
}

function showState(kind) {
  const labels = {
    "signed-in": "Сеанс активний",
    anonymous: "Не ввійшли",
    unknown: "Стан невідомий"
  };
  $("#state").textContent = labels[kind];
}

// Стан сеансу: 204 = ввійшли, 401 = анонім, інше = невизначено (не видаємо за «анонім»).
async function refreshState() {
  try {
    const response = await apiFetch("/api/auth/session-check");
    if (response.status === 204) showState("signed-in");
    else if (response.status === 401) showState("anonymous");
    else showState("unknown");
  } catch {
    showState("unknown");
  }
}

function clearProfile() {
  profileBox.textContent = "—";
  incidentBox.textContent = "—";
}

// Лише явно дозволені поля через textContent.
async function loadProfile() {
  try {
    const response = await apiFetch("/api/me");
    if (response.status === 401) {
      clearProfile();
      profileBox.textContent = "401: не ввійшли";
      showState("anonymous");
      return;
    }
    if (!response.ok || !isJson(response)) {
      profileBox.textContent = `Помилка профілю: ${response.status}`;
      return;
    }
    const me = await response.json();
    profileBox.textContent = `Користувач: ${me.userName}\nРоль: ${me.role}\nId: ${me.userId}`;
    showState("signed-in");
  } catch {
    profileBox.textContent = "Помилка мережі";
    showState("unknown");
  }
}

function problemText(problem) {
  if (!problem) return "";
  const messages = problem.errors ? Object.values(problem.errors).flat().join("; ") : "";
  return [problem.title, messages].filter(Boolean).join(": ");
}

// 1. Реєстрація: 201 і БЕЗ автоматичного входу.
$("#register").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  form.elements.password.value = "";
  try {
    const response = await apiFetch("/api/auth/register", jsonBody(data));
    const body = isJson(response) ? await response.json() : null;
    result.textContent = response.status === 201
      ? `Register: 201, користувач ${body.userName}. Тепер увійдіть.`
      : `Register: ${response.status} ${problemText(body)}`;
  } catch {
    result.textContent = "Register: помилка мережі";
  }
});

// 2. Вхід, далі профіль.
$("#login").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = Object.fromEntries(new FormData(form));
  form.elements.password.value = "";
  try {
    const response = await apiFetch("/api/auth/login", jsonBody(data));
    result.textContent = `Login: ${response.status}`;
    await refreshState();
    if (response.status === 204) await loadProfile();
  } catch {
    result.textContent = "Login: помилка мережі";
  }
});

$("#me").addEventListener("click", loadProfile);

// 3. Створення інциденту: у JSON НЕМАЄ власника, ролі, статусу чи id.
$("#incident").addEventListener("submit", async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const payload = {
    title: data.get("title"),
    description: data.get("description"),
    severity: data.get("severity"),
    occurredAtUtc: new Date(data.get("occurredAt")).toISOString()
  };
  try {
    const response = await apiFetch("/api/incidents", jsonBody(payload));
    const body = isJson(response) ? await response.json() : null;
    if (response.status === 201) {
      incidentBox.textContent = `201: створено «${body.title}» (статус ${body.status}), id ${body.id}`;
      form.reset();
      setDefaultTime();
    } else if (response.status === 401) {
      incidentBox.textContent = "401: спершу увійдіть";
      showState("anonymous");
    } else {
      incidentBox.textContent = `${response.status}: ${problemText(body)}`;
    }
  } catch {
    incidentBox.textContent = "Помилка мережі";
  }
});

// 4. Вихід: серверний sign-out, далі очищення UI і повторний /api/me (очікуємо 401).
$("#logout").addEventListener("click", async () => {
  try {
    const response = await apiFetch("/api/auth/logout", { method: "POST" });
    result.textContent = `Logout: ${response.status}`;
    clearProfile();
    await refreshState();
    await loadProfile();
  } catch {
    result.textContent = "Logout: помилка мережі";
  }
});

function setDefaultTime() {
  const past = new Date(Date.now() - 5 * 60 * 1000);
  const local = new Date(past.getTime() - past.getTimezoneOffset() * 60000);
  $("#incident").elements.occurredAt.value = local.toISOString().slice(0, 16);
}

setDefaultTime();
refreshState();
