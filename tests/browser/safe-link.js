(() => {
    const results = [];
    const check = (condition, message) => {
        if (!condition) throw new Error(`FAIL: ${message}`);
        results.push(`ok - ${message}`);
    };
    const protocolOnly = value => {
        try {
            const url = new URL(value, LINK_BASE);
            return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
        } catch {
            return null;
        }
    };
    const cases = [
        ["/browser-lab.html#20000000-0000-0000-0000-000000000001","http://localhost:5080/browser-lab.html#20000000-0000-0000-0000-000000000001"],
        ["//localhost:4174/", null],
        ["HTTP://LOCALHOST:5080/health", "http://localhost:5080/health"],
        ["mailto:analyst@example.test", null],
        ["//localhost:5080/a/../health?mode=1#part", "http://localhost:5080/health?mode=1#part"],
        ["https://localhost:5080/health", null],
        ["incidents/../../browser-lab.html?from=test", "http://localhost:5080/browser-lab.html?from=test"]

    ];
    const startHref = location.href;
    const table = [];
    for (const [raw, expected] of cases) {
        const parsed = new URL(raw, LINK_BASE);
        const actual = safeSameOriginUrl(raw);
        check(actual === expected, `policy ${raw} -> ${expected}`);
        if (actual !== null) {
            check(safeSameOriginUrl(actual) === actual, `stable ${actual}`);
        }
        table.push({ raw, protocol: parsed.protocol, origin: parsed.origin,
            policy: actual === null ? "reject" : "allow", normalized: actual, protocolOnly: protocolOnly(raw)

        });
        
    }
    console.table(table);

    const anchor = document.querySelector("#safe-link");
    const label = `<b>Картка</b> & "Alice"`;
    renderSafeLink(anchor, cases[0][0], label);
    check(anchor.getAttribute("href") === cases[0][1], "anchor href = input 1");
    check(anchor.textContent === label && anchor.childElementCount === 0, "label is literal text");
    renderSafeLink(anchor, cases[4][0], "Health z query");
    check(anchor.getAttribute("href") === cases[4][1], "same anchor href = input 5");
    check(document.querySelectorAll("a#safe-link").length === 1, "still one anchor");
    check(anchor.getAttributeNames().every(name => name === "id" || name === "href"), "no inline haldler attributes");
    renderSafeLink(anchor, cases[0][0], label);
    check(location.href === startHref, "no navigation happened");
    console.log(results.join("\n"));
    console.log(`PASS: ${results.lenght} checks`); 
})();