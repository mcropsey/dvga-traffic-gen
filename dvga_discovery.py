#!/usr/bin/env python3
"""
dvga_discovery.py — API discovery for DVGA (github.com/dolevf/Damn-Vulnerable-GraphQL-Application)

Only run this against a DVGA instance you own / are authorised to test.
DVGA is an intentionally vulnerable practice target for API security learning.

What it does, in three passes:
  1. SCHEMA   : run a GraphQL introspection query and list every documented
                type, query field, and mutation field (the GraphQL equivalent
                of VAMPI's OpenAPI spec pass).
  2. PROBE    : brute a wordlist of DVGA HTTP endpoints, report status codes.
  3. LIVE     : create + log in, then actually call every known GraphQL
                operation and record status + response shape.

Target URL comes from dvga_config.yaml (base_url + graphql_path). The CLI can
override per-run.

Usage:
  python3 dvga_discovery.py                          # reads dvga_config.yaml
  python3 dvga_discovery.py -c other.yaml            # use a different config file
  python3 dvga_discovery.py -u http://TARGET:5000    # override base_url for this run
  python3 dvga_discovery.py --no-live                # schema + probe only, no writes
  python3 dvga_discovery.py --json out.json          # dump full results to JSON

Requires: requests pyyaml  (pip install -r requirements.txt)
"""

import argparse
import json
import os
import sys

try:
    import requests
except ImportError:
    sys.exit("Missing dependency. Run: pip install requests")

import dvga_common as dv

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
DEFAULT_CONFIG = "dvga_config.yaml"

# DVGA HTTP endpoints to probe blind (app.py url_rules + common paths).
PROBE_PATHS = [
    "/", "/graphql", "/graphiql", "/audit", "/solutions",
    "/difficulty/easy", "/difficulty/hard", "/start_over", "/subscriptions",
    "/about", "/login", "/admin", "/debug", "/api", "/api/v1",
    "/.env", "/robots.txt", "/openapi.json", "/swagger.json",
]

# Built-in DVGA GraphQL operation map — the ground truth for the LIVE pass.
# Each entry: (kind, operation-name, description, needs-write).
# kind is one of: query | mutation
DVGA_OPERATIONS = [
    ("query",    "pastes",               "list pastes (public/limit/filter)",      False),
    ("query",    "paste",                "get a single paste by id",               False),
    ("query",    "systemHealth",         "system health / load string",            False),
    ("query",    "systemUpdate",         "system update string",                   False),
    ("query",    "systemDebug",          "ps-like debug output",                   False),
    ("query",    "users",                "list all users (id/username)",           False),
    ("query",    "search",               "search users + pastes by keyword",       False),
    ("query",    "audits",               "list audit entries",                     False),
    ("query",    "me",                   "current user (needs token arg)",         True),
    ("mutation", "createPaste",          "create a paste",                         True),
    ("mutation", "editPaste",            "edit a paste",                           True),
    ("mutation", "deletePaste",          "delete a paste",                         True),
    ("mutation", "uploadPaste",          "upload a paste from a file",             True),
    ("mutation", "importPaste",          "import a paste from a remote host",      True),
    ("mutation", "createUser",           "create a user",                          True),
    ("mutation", "login",                "login -> access/refresh token",          False),
]

INTROSPECTION_QUERY = """
query Introspection {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields(includeDeprecated: true) { name }
      inputFields { name }
    }
    directives { name }
  }
}
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def shape(resp):
    """Compact description of a GraphQL response body."""
    if resp is None:
        return "ERR"
    if resp.status_code == 204 or not (resp.content or b"").strip():
        return "empty"
    ct = resp.headers.get("content-type", "")
    if "json" in ct:
        try:
            data = resp.json()
            if isinstance(data, dict):
                keys = list(data.keys())
                extra = ""
                if "errors" in data and data["errors"]:
                    extra = " +errors[" + str(len(data["errors"])) + "]"
                return "json{" + ",".join(keys[:8]) + "}" + extra
            return f"json:{type(data).__name__}"
        except ValueError:
            return "json(unparseable)"
    return f"{ct.split(';')[0] or 'text'}:{len(resp.text)}b"


def line(kind, name, resp, note=""):
    sh = shape(resp)
    print(f"  {sh}")
    if note:
        print(f"       ({note})")


def gql(session, base, graphql_path, query, variables=None, timeout=8):
    url = base.rstrip("/") + graphql_path
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    try:
        return session.post(url, json=payload,
                            headers={"Content-Type": "application/json"},
                            timeout=timeout)
    except requests.RequestException as e:
        print(f"  ERR   {e.__class__.__name__}")
        return None


# ---------------------------------------------------------------------------
# Pass 1 — GraphQL introspection (the "spec")
# ---------------------------------------------------------------------------
def discover_schema(session, base, graphql_path, results, timeout):
    print("\n=== [1] GraphQL introspection (schema) ===")
    r = gql(session, base, graphql_path, INTROSPECTION_QUERY, timeout=timeout)
    if r is None:
        print("  [-] introspection request failed (transport).")
        results["schema"] = {"found": False, "operations": []}
        return []

    try:
        body = r.json()
    except ValueError:
        print(f"  [-] introspection returned HTTP {r.status_code} but not JSON.")
        results["schema"] = {"found": False, "operations": []}
        return []

    if "errors" in body and body["errors"]:
        print(f"  [-] introspection blocked: {body['errors'][0].get('message', '')}")
        results["schema"] = {"found": False, "operations": []}
        return []

    data = (body.get("data") or {}).get("__schema") or {}
    types = data.get("types") or []

    # Collect query + mutation root fields.
    ops = []
    qtype = (data.get("queryType") or {}).get("name", "Query")
    mtype = (data.get("mutationType") or {}).get("name", "Mutation")

    for t in types:
        if t.get("name") == qtype:
            for f in t.get("fields") or []:
                ops.append({"kind": "query", "name": f.get("name")})
        elif t.get("name") == mtype:
            for f in t.get("fields") or []:
                ops.append({"kind": "mutation", "name": f.get("name")})

    print(f"  [+] query root    : {qtype}")
    print(f"  [+] mutation root : {mtype}")
    print(f"  [+] {len(types)} types, {len(ops)} root operations:")
    for o in ops:
        print(f"       {o['kind']:<8} {o['name']}")

    results["schema"] = {"found": True, "query_type": qtype,
                         "mutation_type": mtype, "operations": ops}
    return ops


# ---------------------------------------------------------------------------
# Pass 2 — blind HTTP path probe
# ---------------------------------------------------------------------------
def probe_paths(session, base, results, paths, timeout):
    print("\n=== [2] Common-path probe (DVGA HTTP endpoints) ===")
    found = []
    for p in paths:
        url = base.rstrip("/") + p
        try:
            r = session.get(url, timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code != 404:
            print(f"  {r.status_code:>4}  GET {p:<28} {shape(r)}")
            found.append({"path": p, "status": r.status_code, "shape": shape(r)})
    print(f"  [+] {len(found)} interesting paths (non-404).")
    results["probe"] = found
    return found


# ---------------------------------------------------------------------------
# Pass 3 — live calls (create user, login, exercise every operation)
# ---------------------------------------------------------------------------
def live(session, base, graphql_path, results, username=None, password=None,
         token=None, timeout=8):
    print("\n=== [3] Live GraphQL operation exercise ===")
    username = username or ("disco_" + dv.rand_username("x"))
    password = password or "Passw0rd!" + dv.rand_password()[-6:]

    if not token:
        # create user
        r = gql(session, base, graphql_path, """
          mutation($u: String!, $e: String!, $p: String!) {
            createUser(userData: {username: $u, email: $e, password: $p}) {
              user { id username }
            }
          }
        """, {"u": username, "e": dv.rand_email(username), "p": password},
          timeout=timeout)
        if r is not None:
            print(f"  createUser({username}) -> {shape(r)}")
        # login
        r = gql(session, base, graphql_path, """
          mutation($u: String!, $p: String!) {
            login(username: $u, password: $p) { accessToken refreshToken }
          }
        """, {"u": username, "p": password}, timeout=timeout)
        if r is not None:
            print(f"  login({username}) -> {shape(r)}")
            try:
                token = (r.json().get("data") or {}).get("login", {}).get("accessToken")
            except (ValueError, AttributeError):
                token = None

    if token:
        print(f"  [+] auth token acquired ({token[:12]}...)")
    else:
        print("  [-] No token — the me(token:) call will likely error.")

    called = []
    for kind, name, desc, needs_write in DVGA_OPERATIONS:
        # Build a minimal valid operation that exercises `name`.
        if kind == "query":
            if name == "me":
                q = 'query { me(token: "%s") { id username } }' % (token or "")
            elif name == "pastes":
                q = "query { pastes(public: true) { id title } }"
            elif name == "paste":
                q = "query { paste(id: 1) { id title } }"
            elif name == "systemDebug":
                q = "query { systemDebug }"
            elif name == "users":
                q = "query { users { id username } }"
            elif name == "search":
                q = 'query { search(keyword: "a") { ... on UserObject { id } } }'
            elif name == "audits":
                q = "query { audits { id } }"
            else:
                q = "query { %s }" % name
        else:
            if name == "createPaste":
                q = 'mutation { createPaste(title: "d", content: "d", public: true, burn: false) { paste { id } } }'
            elif name == "editPaste":
                q = "mutation { editPaste(id: 1, title: \"d\", content: \"d\") { paste { id } } }"
            elif name == "deletePaste":
                q = "mutation { deletePaste(id: 99999999) { result } }"
            elif name == "uploadPaste":
                q = 'mutation { uploadPaste(content: "d", filename: "d.txt") { result } }'
            elif name == "importPaste":
                q = 'mutation { importPaste(scheme: "http", host: "localhost", path: "/", port: 80) { result } }'
            elif name == "createUser":
                q = 'mutation { createUser(userData: {username: "d2", email: "d2@e.com", password: "D2pass!"}) { user { id } } }'
            elif name == "login":
                q = 'mutation { login(username: "%s", password: "%s") { accessToken } }' % (username, password)
            else:
                q = "mutation { %s }" % name

        r = gql(session, base, graphql_path, q, timeout=timeout)
        if r is None:
            continue
        print(f"  {kind:<8} {name:<14} -> {shape(r)}")
        called.append({"kind": kind, "name": name, "desc": desc,
                       "status": r.status_code, "shape": shape(r),
                       "needs_write": needs_write})

    results["live"] = {"username": username, "token": bool(token), "calls": called}
    return called


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="DVGA API discovery")
    ap.add_argument("-c", "--config", default=DEFAULT_CONFIG,
                    help="path to YAML config file (default %(default)s)")
    ap.add_argument("-u", "--url", help="base URL; overrides base_url from the config file")
    ap.add_argument("--token", help="reuse an existing access token instead of creating a user")
    ap.add_argument("--username", help="username for the live pass")
    ap.add_argument("--password", help="password for the live pass")
    ap.add_argument("--no-live", action="store_true", help="skip the live/write pass")
    ap.add_argument("--json", metavar="FILE", help="write full results to a JSON file")
    args = ap.parse_args()

    if os.path.exists(args.config):
        cfg = dv.load_config(args.config)
    else:
        cfg = {}
        print(f"  [-] config file not found: {args.config}; using defaults")

    timeout = dv.timeout(cfg)
    base = (args.url or dv.base_url(cfg)).rstrip("/")
    gpath = dv.graphql_path(cfg)

    print(f"DVGA discovery -> {base} (graphql at {gpath})")
    print("Reminder: only run against a target you are authorised to test.")

    session = requests.Session()
    session.headers["User-Agent"] = "dvga-discovery/1.0"
    gw_key = os.environ.get("GATEWAY_SUBSCRIPTION_KEY", "").strip() or str(
        (cfg.get("target") or {}).get("subscription_key", "") or "").strip()
    if gw_key:
        hdr = str((cfg.get("target") or {}).get("subscription_key_header", "Ocp-Apim-Subscription-Key"))
        session.headers[hdr] = gw_key
    results = {"base": base}

    # Reachability: probe the GraphQL endpoint (a minimal __typename query).
    # DVGA's root "/" is not a reliable indicator (it may 404/redirect/reset),
    # so we check /graphql directly.
    reachable = False
    try:
        reach = session.post(base + gpath, json={"query": "{ __typename }"},
                             headers={"Content-Type": "application/json"}, timeout=timeout)
        body = reach.json() if reach.headers.get("content-type", "").find("json") >= 0 else None
        reachable = (reach.status_code < 500) and (body is not None)
        print(f"  [+] reachable — {base + gpath} returned {reach.status_code}")
    except requests.RequestException as e:
        print(f"  [-] {base + gpath} request failed: {e}")
    if not reachable:
        # Fallback: at least confirm the host answers on root.
        try:
            root = session.get(base + "/", timeout=timeout)
            print(f"  [~] graphql endpoint unresponsive, but root returned {root.status_code}")
        except requests.RequestException:
            sys.exit("Target unreachable. Check base_url in the config, or pass -u http://host:port")

    discover_schema(session, base, gpath, results, timeout)
    probe_paths(session, base, results, PROBE_PATHS, timeout)
    if not args.no_live:
        live(session, base, gpath, results,
             token=args.token, username=args.username, password=args.password,
             timeout=timeout)
    else:
        print("\n=== [3] Live GraphQL operation exercise === (skipped: --no-live)")

    if args.json:
        with open(args.json, "w") as f:
            json.dump(results, f, indent=2, default=str)
        print(f"\n[+] Full results written to {args.json}")

    print("\nDone.")


if __name__ == "__main__":
    main()
