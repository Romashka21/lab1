#!/usr/bin/env python3
"""ЛР 4: повторювані HTTP-сценарії Alice/Bob/Morgan для PoC і retest (лише локальний стенд).

Запуск із кореня проєкту (PowerShell, пароль уже в $env:SeedUsers__Password):
    py -3 tests/http/lab04_scenarios.py start
    py -3 tests/http/lab04_scenarios.py read
    ... (див. SCENARIOS нижче) або all

Скрипт не друкує пароль і cookie: cookie живе лише в пам'яті процесу.
"""
import http.client
import json
import os
import sys
import uuid

HOST, PORT = "localhost", 5080
U = {
    "alice_incident": "20000000-0000-0000-0000-000000000001",
    "bob_incident": "20000000-0000-0000-0000-000000000002",
    "bob_search_incident": "20000000-0000-0000-0000-000000000004",
    "alice_comment": "30000000-0000-0000-0000-000000000001",
    "bob_comment": "30000000-0000-0000-0000-000000000002",
    "internal_comment": "30000000-0000-0000-0000-000000000003",
}

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:  # noqa: BLE001
    pass


class Session:
    """Окремий клієнт = окрема cookie (як окремий браузер)."""

    def __init__(self, name):
        self.name = name
        self.cookies = {}

    def call(self, method, path, body=None, show=True):
        conn = http.client.HTTPConnection(HOST, PORT, timeout=15)
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json; charset=utf-8"
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        conn.request(method, path, body=data, headers=headers)
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8", errors="replace")
        for key, value in resp.getheaders():
            if key.lower() == "set-cookie":
                pair = value.split(";", 1)[0]
                name, _, val = pair.partition("=")
                if val:
                    self.cookies[name] = val
                else:
                    self.cookies.pop(name, None)
        conn.close()
        parsed = None
        try:
            parsed = json.loads(raw) if raw else None
        except ValueError:
            parsed = None
        if show:
            shown = json.dumps(parsed, ensure_ascii=False) if parsed is not None else raw
            if len(shown) > 400:
                shown = shown[:400] + " …"
            print(f"  {self.name:9} {method:6} {path} -> {resp.status} {shown}")
        return resp.status, parsed

    def login(self):
        password = os.environ.get("SeedUsers__Password")
        if not password:
            sys.exit("SeedUsers__Password не задано в цьому терміналі.")
        status, _ = self.call("POST", "/api/auth/login",
                              {"userName": self.name, "password": password}, show=False)
        print(f"  {self.name:9} login -> {status}")
        return self


_SESSIONS = {}


def user(name):
    """Один login на користувача за запуск (не вичерпуємо rate limit входу ЛР 3)."""
    if name not in _SESSIONS:
        _SESSIONS[name] = Session(name).login()
    return _SESSIONS[name]


def anon():
    return Session("anonymous")


def new_incident(session, prefix):
    title = f"{prefix}-{uuid.uuid4().hex[:8]}"
    status, body = session.call("POST", "/api/incidents", {
        "title": title,
        "description": "Синтетичний запис для локального сценарію ЛР 4.",
        "severity": "Low",
        "occurredAtUtc": "2026-10-01T10:00:00+00:00",
    })
    if status != 201:
        sys.exit(f"Не вдалося створити інцидент: {status}")
    return body["id"]


def header(text):
    print()
    print("=" * 8, text)


def s_start():
    header("START: login, профілі, анонім")
    for name in ("alice", "bob", "morgan"):
        user(name).call("GET", "/api/me")
    a = anon()
    a.call("GET", "/api/me")
    a.call("POST", "/api/incidents", {})


def s_read():
    header("READ (A-02 / A-03 / A-03R): Alice → своє, Alice → Bob, Morgan → Alice")
    alice, morgan = user("alice"), user("morgan")
    alice.call("GET", f"/api/incidents/{U['alice_incident']}")
    alice.call("GET", f"/api/incidents/{U['bob_incident']}")
    alice.call("GET", f"/api/incidents/{uuid.uuid4()}")
    morgan.call("GET", f"/api/incidents/{U['alice_incident']}")
    anon().call("GET", f"/api/incidents/{U['alice_incident']}")


def s_update():
    header("UPDATE (A-04): Alice змінює інцидент Bob? стан до/після читає Bob")
    alice, bob = user("alice"), user("bob")
    _, before = bob.call("GET", f"/api/incidents/{U['bob_incident']}")
    alice.call("PUT", f"/api/incidents/{U['bob_incident']}", {
        "title": "Змінено Alice (PoC)",
        "description": "Alice змінила чужий інцидент через підстановку id.",
    })
    _, after = bob.call("GET", f"/api/incidents/{U['bob_incident']}")
    changed = (before or {}).get("title") != (after or {}).get("title")
    print(f"  РЕЗУЛЬТАТ: title Bob {'ЗМІНЕНО (IDOR)' if changed else 'не змінився'}")


def s_delete():
    header("DELETE (A-04): Bob створює інцидент, Alice намагається видалити")
    alice, bob = user("alice"), user("bob")
    incident_id = new_incident(bob, "DEL-PoC")
    alice.call("DELETE", f"/api/incidents/{incident_id}")
    status, _ = bob.call("GET", f"/api/incidents/{incident_id}")
    print(f"  РЕЗУЛЬТАТ: інцидент Bob {'ВИДАЛЕНО (IDOR)' if status == 404 else 'на місці'}")
    if status == 200:
        bob.call("DELETE", f"/api/incidents/{incident_id}")


def s_vertical():
    header("VERTICAL (A-06 / A-08): Reporter Alice виконує triage і підміняє status у update")
    alice = user("alice")
    first = new_incident(alice, "VERT-triage")
    alice.call("POST", f"/api/incidents/{first}/triage", {"note": "Reporter робить privileged transition"})
    alice.call("GET", f"/api/incidents/{first}")
    second = new_incident(alice, "VERT-forged")
    alice.call("PUT", f"/api/incidents/{second}", {
        "title": f"VERT-forged-{uuid.uuid4().hex[:6]}",
        "description": "Звичайний update із підробленим полем status.",
        "status": "Closed",
    })
    alice.call("GET", f"/api/incidents/{second}")


def s_analyst():
    header("ANALYST (A-07): Morgan робить triage New→Triaged, але не редагує вміст")
    alice, morgan = user("alice"), user("morgan")
    incident_id = new_incident(alice, "ANL")
    morgan.call("POST", f"/api/incidents/{incident_id}/triage", {"note": "Первинну оцінку виконано"})
    morgan.call("POST", f"/api/incidents/{incident_id}/triage", {"note": "повторно"})
    morgan.call("PUT", f"/api/incidents/{incident_id}", {
        "title": "Morgan змінює чужий вміст",
        "description": "Analyst не має права на content update.",
    })
    alice.call("GET", f"/api/incidents/{incident_id}")


def s_child():
    header("CHILD (A-12): коментарі за прямим id та internal comment")
    alice, morgan = user("alice"), user("morgan")
    alice.call("GET", f"/api/incident-comments/{U['bob_comment']}")
    alice.call("GET", f"/api/incident-comments/{U['internal_comment']}")
    alice.call("GET", f"/api/incident-comments/{U['alice_comment']}")
    morgan.call("GET", f"/api/incident-comments/{U['internal_comment']}")
    _, details = alice.call("GET", f"/api/incidents/{U['alice_incident']}", show=False)
    ids = [c["id"] for c in (details or {}).get("comments", [])]
    print(f"  alice     details-проєкція: коментарі {ids}")
    _, details = morgan.call("GET", f"/api/incidents/{U['alice_incident']}", show=False)
    ids = [c["id"] for c in (details or {}).get("comments", [])]
    print(f"  morgan    details-проєкція: коментарі {ids}")


def s_a11():
    header("A-11: search і severity-summary")
    alice, morgan = user("alice"), user("morgan")
    alice.call("GET", "/api/incidents/search?q=O%27Brien")
    alice.call("GET", "/api/incidents/severity-summary")
    morgan.call("GET", "/api/incidents/search?q=O%27Brien")
    morgan.call("GET", "/api/incidents/severity-summary")
    a = anon()
    a.call("GET", "/api/incidents/search?q=O%27Brien")
    a.call("GET", "/api/incidents/severity-summary")


def s_a10():
    header("A-10: чужий і неіснуючий id (політика 404)")
    alice = user("alice")
    alice.call("GET", f"/api/incidents/{U['bob_incident']}")
    alice.call("GET", f"/api/incidents/{uuid.uuid4()}")


def s_audit():
    header("AUDIT (A-09): Reporter → triage; порівняйте traceId з рядком authorization.denied у вікні API")
    alice = user("alice")
    incident_id = new_incident(alice, "AUD")
    alice.call("POST", f"/api/incidents/{incident_id}/triage", {"note": "спроба Reporter"})


SCENARIOS = {
    "start": s_start, "read": s_read, "update": s_update, "delete": s_delete,
    "vertical": s_vertical, "analyst": s_analyst, "child": s_child,
    "a10": s_a10, "a11": s_a11, "audit": s_audit,
}

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in (*SCENARIOS, "all", "check"):
        sys.exit("Використання: py -3 tests/http/lab04_scenarios.py "
                 + "|".join([*SCENARIOS, "all", "check"]))
    if sys.argv[1] == "check":
        print({"password_present": bool(os.environ.get("SeedUsers__Password"))})
    elif sys.argv[1] == "all":
        for scenario in SCENARIOS.values():
            scenario()
    else:
        SCENARIOS[sys.argv[1]]()
