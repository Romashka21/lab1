// ЛР 6: один клієнтський helper antiforgery для всіх сторінок із mutation (auth-lab, browser-lab).
// Request token одержуємо lazy перед першою mutation саме на поточній сторінці й тримаємо лише
// в пам'яті (не в localStorage/sessionStorage). F5 або перехід на іншу сторінку = нова пам'ять.
// Cookie-частину пари (SecureLab.Antiforgery, HttpOnly) зберігає й надсилає браузер, JS її не бачить.
(() => {
  const HEADER = "X-SecureLab-CSRF";
  const TOKEN_ROUTE = "/api/auth/csrf-token";
  let token = null;
  let pending = null;
  let generation = 0;

  // Після login/logout (новий principal) старий токен недійсний.
  function reset() {
    token = null;
    pending = null;
    generation++;
  }

  async function ensureToken() {
    if (token) return token;
    if (pending) return pending;
    const current = generation;
    const operation = (async () => {
      const response = await fetch(TOKEN_ROUTE, { credentials: "same-origin", cache: "no-store" });
      if (!response.ok) {
        throw new Error(`Token request failed: ${response.status}`);
      }
      const data = await response.json();
      if (current !== generation) {
        throw new Error("Сеанс змінився; потрібен новий токен.");
      }
      if (typeof data.token !== "string" || !data.token) {
        throw new Error("Некоректна відповідь видачі токена.");
      }
      token = data.token;
      return token;
    })();
    pending = operation;
    try {
      return await operation;
    } finally {
      if (pending === operation) pending = null;
    }
  }

  // Лише POST/PUT/PATCH/DELETE і лише свій origin: токен не залишає застосунок.
  // Після 4xx запит автоматично НЕ повторюється.
  async function mutate(url, options = {}) {
    const method = (options.method || "POST").toUpperCase();
    if (!["POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      throw new Error("Для читання використовуйте звичайний fetch.");
    }
    const target = new URL(url, location.href);
    if (target.origin !== location.origin) {
      throw new Error("Токен не надсилається на інший origin.");
    }
    const headers = new Headers(options.headers);
    headers.set(HEADER, await ensureToken());
    const response = await fetch(target, { ...options, method, headers, credentials: "same-origin" });
    if (response.status === 400 || response.status === 401) reset();
    return response;
  }

  window.SecureLabCsrf = Object.freeze({ reset, ensureToken, mutate });
  window.addEventListener("pageshow", reset);
})();
