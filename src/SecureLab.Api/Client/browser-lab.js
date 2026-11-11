let current;
const id = () => encodeURIComponent(document.querySelector("#incident-id").value.trim());
const status = document.querySelector("#status");

// ЛР 5: єдиний safe render helper для Description і IncidentComment.Text.
// Структуру (елементи) створює код, а значення з API потрапляє лише в DOM text node,
// тому HTML parser його не розбирає. replaceChildren прибирає попередній вміст (повторний render).
function setPlainText(element, value) {
  element.replaceChildren(document.createTextNode(value ?? ""));
  return element;
}

async function load() {
  const response = await fetch(`/api/incidents/${id()}`);
  status.textContent = `GET: ${response.status}`;
  if (!response.ok) return;
  current = await response.json();
  document.querySelector("#title").textContent = current.title;
  setPlainText(document.querySelector("#description"), current.description);
  const paragraphs = (current.comments ?? []).map(comment =>
    setPlainText(document.createElement("p"), comment.text));
  document.querySelector("#comments").replaceChildren(...paragraphs);
  document.querySelector("#edit").elements.description.value = current.description;
}
document.querySelector("#load").addEventListener("click", load);
document.querySelector("#edit").addEventListener("submit", async event => {
  event.preventDefault();
  const response = await fetch("/api/incidents", { method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title: event.currentTarget.elements.title.value, description: event.currentTarget.elements.description.value,
      severity: "Low", occurredAtUtc: new Date().toISOString() }) });
  status.textContent = `POST: ${response.status}`;
  if (response.ok) {
    const created = await response.json();
    document.querySelector("#incident-id").value = created.id;
    await load();
  }
});

const LINK_BASE = "http://localhost:5080/";
const LINK_ORIGIN = new URL(LINK_BASE).origin;

function safeSameOriginUrl(value) {
  if (typeof value !== "string" || value.trim() === "") return null;
  let url;
  try {
    url = new URL(value, LINK_BASE);
  } catch {
    return null;
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") return null;
  if (url.origin !== LINK_ORIGIN) return null;
  return url.href;
}

function renderSafeLink(anchor, value, label) {
  const href = safeSameOriginUrl(value);
  if (href == null) {
    anchor.removeAttribute("href");
  } else {
    anchor.href = href;
  }
  anchor.textContent = label;
  return href;
}
