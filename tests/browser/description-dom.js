// ЛР 5 (Відмінно): автоматичний тест ФАКТИЧНОГО DOM сторінки /browser-lab.html.
// Запуск: увійти (Alice або Morgan) → відкрити /browser-lab.html → Ctrl+Shift+R →
// у поле «Guid інциденту» вставити Guid свого інциденту з marker в описі →
// вставити весь цей файл у DevTools Console → Enter.
// Перевіряє: Description і кожен comments[].text стають лише текстовими вузлами,
// повторний render не дублює вузли, marker не виконується, позитивні рядки не пошкоджені.
// Створює 2 синтетичні інциденти (позитивні рядки) від імені поточного користувача.
await (async () => {
  const results = [];
  const check = (condition, message) => {
    if (!condition) throw new Error(`FAIL: ${message}`);
    results.push(`ok - ${message}`);
  };
  const markerValue = () =>
    document.querySelector("#lab05-marker-target").getAttribute("data-lab05-marker");
  const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
  const idInput = document.querySelector("#incident-id");
  const box = document.querySelector("#description");
  const commentsBox = document.querySelector("#comments");
  const SEED_INCIDENT = "20000000-0000-0000-0000-000000000001";   // має comment-5 з marker

  async function renderAndCheck(incidentId, label) {
    const response = await fetch(`/api/incidents/${encodeURIComponent(incidentId)}`);
    check(response.status === 200, `${label}: GET -> 200 (actual ${response.status})`);
    const data = await response.json();
    idInput.value = incidentId;
    await load();
    check(box.textContent === data.description, `${label}: description text equals API value`);
    check(box.childElementCount === 0, `${label}: description has no HTML child elements`);
    const paragraphs = [...commentsBox.querySelectorAll("p")];
    const comments = data.comments ?? [];
    check(paragraphs.length === comments.length, `${label}: one <p> per comment (${comments.length})`);
    comments.forEach((comment, index) => {
      check(paragraphs[index].textContent === comment.text, `${label}: comment ${index + 1} text equals API value`);
      check(paragraphs[index].childElementCount === 0, `${label}: comment ${index + 1} has no HTML child elements`);
    });
    return data;
  }

  // 1. Fixture: власний інцидент із канонічним marker в описі.
  const fixtureId = idInput.value.trim();
  check(fixtureId.length > 0, "fixture Guid entered");
  check(markerValue() === null, "page reloaded before test (marker attribute absent)");
  const fixture = await renderAndCheck(fixtureId, "fixture");
  check(fixture.description.includes("data-lab05-marker"), "fixture description contains canonical marker");

  // 2. Другий sink: seed-інцидент Alice з коментарем-marker (comment-5).
  const seed = await renderAndCheck(SEED_INCIDENT, "seed comments");
  check((seed.comments ?? []).some(c => c.text.includes("data-lab05-marker")), "seed has marker comment");

  // 3. Повторний render без дублювання.
  const expectedComments = (seed.comments ?? []).length;
  await load();
  await load();
  check(commentsBox.querySelectorAll("p").length === expectedComments, "re-render does not duplicate comments");
  check(box.childNodes.length === 1, "re-render keeps a single text node in description");

  // 4. Marker не виконався в жодному render.
  await pause(500);
  check(markerValue() === null, "marker did not execute");

  // 5. Позитивні рядки: лапки, </>, HTML-like, Unicode і довгий текст.
  const positives = [
    `Користувач O'Brien написав "терміново": 5 < 7 і 9 > 3, <b>жирний</b> текст, Київ — Ω`,
    "А".repeat(3990)
  ];
  for (const [index, value] of positives.entries()) {
    const created = await fetch("/api/incidents", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ title: `DOM-REG ${Date.now()} ${index}`, description: value,
        severity: "Low", occurredAtUtc: new Date().toISOString() })
    });
    check(created.status === 201, `positive ${index + 1}: POST -> 201 (actual ${created.status})`);
    const body = await created.json();
    const data = await renderAndCheck(body.id, `positive ${index + 1}`);
    check(data.description === value, `positive ${index + 1}: stored value unchanged`);
  }

  // Повертаємо fixture на екран.
  idInput.value = fixtureId;
  await load();
  console.log(results.join("\n"));
  console.log(`PASS: ${results.length} checks — Description і comments відображаються як текст`);
})();
