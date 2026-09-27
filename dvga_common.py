#!/usr/bin/env python3
"""
dvga_common.py
==============
Shared helpers for the DVGA traffic generators (dvga_traffic.py, the
*_cycle.py scripts, and the baseline/ + vuln/ challenge scripts).

Keeps config loading, known-user derivation, the GraphQL transport helper,
the login mutation, per-consumer identity headers, JWT crafting, and run
stats in one place so every script behaves consistently.

DVGA (https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) is a
deliberately vulnerable "vulnerable-on-purpose" GraphQL training app.
Point base_url at your own lab only — never at systems you don't own.

DVGA API shape (what makes it different from VAmPI's REST API):
  * ONE endpoint:   POST {base}/graphql   (batch queries allowed)
  * Auth is NOT an Authorization header. DVGA's `me` query takes the token
    as a GraphQL argument:   me(token: "<jwt>") { username }
  * Tokens are JWTs issued by flask_graphql_auth. DVGA's get_identity()
    decodes them with  verify_signature=False, verify_exp=False
    and reads the `identity` claim — so the signature is NEVER checked and
    any JWT carrying an `identity` claim is accepted (JWT-forgery finding).
  * Login:  mutation { login(username: "...", password: "...")
                          { accessToken refreshToken } }
    (The GraphQL selection fields are camelCase: accessToken / refreshToken.
     login() below normalises them back to snake_case Python dict keys.)
  * Tokens are short-lived (access 120 s, refresh 30 s). `login()` is a
    one-shot: call it again any time you need a fresh token.

Dependencies:  pip install requests pyyaml
"""

import base64
import json
import os
import random
import string
import sys
import time
from typing import Any, Dict, List, Optional

import requests
import yaml


DEFAULT_CONFIG = "dvga_config.yaml"


# ── optional API-gateway key ─────────────────────────────────────────────────
# If base_url sits behind a gateway that requires a subscription key, set
# GATEWAY_SUBSCRIPTION_KEY in the environment or `target.subscription_key`
# in the config and the header name in `target.subscription_key_header`.
# Empty -> no-op (direct DVGA hosts behave exactly as-is).
def _gateway_key() -> str:
    key = os.environ.get("GATEWAY_SUBSCRIPTION_KEY", "").strip()
    if key:
        return key
    try:
        if os.path.exists(DEFAULT_CONFIG):
            with open(DEFAULT_CONFIG) as f:
                cfg = yaml.safe_load(f) or {}
            return str((cfg.get("target") or {}).get("subscription_key", "") or "").strip()
    except Exception:
        pass
    return ""


def _gateway_key_header() -> str:
    try:
        if os.path.exists(DEFAULT_CONFIG):
            with open(DEFAULT_CONFIG) as f:
                cfg = yaml.safe_load(f) or {}
            return str((cfg.get("target") or {}).get("subscription_key_header", "") or "").strip()
    except Exception:
        pass
    return "Ocp-Apim-Subscription-Key"


# ── config loading ───────────────────────────────────────────────────────────
def load_config(path: str = DEFAULT_CONFIG) -> dict:
    if not os.path.exists(path):
        sys.exit(f"Config file not found: {path}\n"
                 f"Create one next to the scripts (see dvga_config.yaml).")
    with open(path) as f:
        return yaml.safe_load(f) or {}


def base_url(cfg: dict) -> str:
    return str((cfg.get("target") or {}).get("base_url", "http://localhost:5013")).rstrip("/")


def graphql_path(cfg: dict) -> str:
    return str((cfg.get("target") or {}).get("graphql_path", "/graphql"))


def timeout(cfg: dict) -> float:
    return float((cfg.get("http") or {}).get("timeout", 10.0))


# ── response parsing (GraphQL envelope: {"data": ...} / {"errors": [...]}) ──
def gql_data(r: Optional[requests.Response]) -> Any:
    """The `data` field of a GraphQL response, or None on error/transport fail."""
    if r is None:
        return None
    try:
        j = r.json()
    except Exception:
        return None
    if isinstance(j, dict):
        return j.get("data")
    return j


def gql_errors(r: Optional[requests.Response]) -> List[Dict[str, Any]]:
    """The `errors` list of a GraphQL response ([] when clean)."""
    if r is None:
        return []
    try:
        j = r.json()
    except Exception:
        return []
    if isinstance(j, dict) and isinstance(j.get("errors"), list):
        return j["errors"]
    return []


def gql_ok(r: Optional[requests.Response]) -> bool:
    """True when the transport succeeded AND GraphQL reported no errors."""
    if r is None or r.status_code // 100 != 2:
        return False
    return len(gql_errors(r)) == 0


def as_list(data: Any) -> List[Any]:
    """DVGA returns bare lists (e.g. data.pastes, data.users); pass the
    `data` dict through and pick the list out of it if needed."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                return v
    return []


# ── known lab users ──────────────────────────────────────────────────────────
def known_users(cfg: dict) -> List[Dict[str, str]]:
    """Return [{username, password, email}] for the configured known lab users.

    DVGA seeds admin/changeme and operator/password123 (see setup.py). These
    are the authenticated identities for the findings phase and the targets
    of the weak-password / brute-force patterns.
    """
    ku = cfg.get("known_users") or {}
    users = ku.get("users") or [
        {"username": "admin", "password": "changeme", "email": "admin@blackhatgraphql.com"},
        {"username": "operator", "password": "password123", "email": "operator@blackhatgraphql.com"},
    ]
    out = []
    for u in users:
        name = u.get("username")
        out.append({
            "username": name,
            "password": u.get("password"),
            "email": u.get("email") or f"{name}@blackhatgraphql.com",
        })
    return out


def known_usernames(cfg: dict) -> List[str]:
    return [u["username"] for u in known_users(cfg)]


def brute_target(cfg: dict) -> str:
    return str((cfg.get("findings") or {}).get("brute_target", "locked-target"))


# ── consumer identity surface ────────────────────────────────────────────────
UAS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/124.0",
    "DVGA-Client/1.0 (Android 14; Pixel 8)",
    "DVGA-Client/1.0 (iOS 17.4; iPhone15,3)",
    "PostmanRuntime/7.37.0",
    "python-requests/2.31.0",
    "okhttp/4.12.0",
]


def consumer_headers(idx: int) -> Dict[str, str]:
    """Each consumer gets a distinct identity surface. Which of these the sensor
    actually counts as a 'consumer' depends on its config (source IP / token
    identity / api key) — vary all of them so at least one dimension lands."""
    octet_a = (idx // 254) % 254 + 1
    octet_b = idx % 254 + 1
    h = {
        "User-Agent": random.choice(UAS),
        "X-Forwarded-For": f"10.{octet_a}.{octet_b}.{random.randint(2, 250)}",
        "X-Api-Client": f"client-{idx:05d}",
    }
    key = _gateway_key()
    if key:
        h[_gateway_key_header()] = key
    return h


def rand_username(tag: str = "user") -> str:
    n = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{tag}_{n}"


def rand_email(username: str) -> str:
    return f"{username}@mail.com"


def rand_password() -> str:
    return "GoodPass" + str(random.randint(1000, 9999)) + "!"


def rand_paste_title(tag: str = "paste") -> str:
    n = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"{tag} {n}"


# ── GraphQL transport ────────────────────────────────────────────────────────
def graphql(base: str, query: str, variables: Optional[dict] = None,
            cfg: Optional[dict] = None,
            headers: Optional[dict] = None,
            timeout: float = 10.0) -> Optional[requests.Response]:
    """POST one operation to {base}/graphql.

    `variables` may be None for inline-argument queries. Returns the
    Response (inspect with gql_data/gql_errors/gql_ok) or None on a
    transport-level failure.
    """
    url = f"{base}{graphql_path(cfg or {})}"
    payload: Dict[str, Any] = {"query": query}
    if variables:
        payload["variables"] = variables
    h = dict(headers or consumer_headers(1))
    h.setdefault("Content-Type", "application/json")
    key = _gateway_key()
    if key:
        h.setdefault(_gateway_key_header(), key)
    try:
        return requests.post(url, json=payload, headers=h, timeout=timeout)
    except requests.RequestException:
        return None


def gql(base: str, query: str, variables: Optional[dict] = None,
        cfg: Optional[dict] = None,
        headers: Optional[dict] = None,
        tout: Optional[float] = None) -> Any:
    """Convenience: graphql() + data extraction in one call (None on failure)."""
    r = graphql(base, query, variables, cfg, headers, tout if tout is not None else 10.0)
    return gql_data(r)


# ── auth ─────────────────────────────────────────────────────────────────────
def login(base: str, username: str, password: str, cfg: Optional[dict] = None,
          hdrs: Optional[dict] = None, timeout: float = 10.0) -> Optional[Dict[str, str]]:
    """Run the login mutation; return {access_token, refresh_token} or None.

    DVGA tokens are short-lived (120 s access / 30 s refresh), so this is a
    one-shot login: call it again any time you need a fresh token.
    """
    query = """
    mutation Login($username: String, $password: String) {
      login(username: $username, password: $password) {
        accessToken
        refreshToken
      }
    }
    """
    r = graphql(base, query, {"username": username, "password": password},
                cfg, hdrs or consumer_headers(1000), timeout)
    data = gql_data(r)
    if not data or not isinstance(data.get("login"), dict):
        return None
    tok = data["login"].get("accessToken")
    if not tok:
        return None
    return {"access_token": tok, "refresh_token": data["login"].get("refreshToken", "")}


def login_token(base: str, username: str, password: str, cfg: Optional[dict] = None,
                hdrs: Optional[dict] = None, timeout: float = 10.0) -> Optional[str]:
    """login() but just the access_token string (or None)."""
    t = login(base, username, password, cfg, hdrs, timeout)
    return t["access_token"] if t else None


def get_tokens(cfg: dict) -> Dict[str, str]:
    """Log in each known lab user once; return {username: access_token}."""
    base = base_url(cfg)
    tout = timeout(cfg)
    users = known_users(cfg)
    tokens = {}
    for i, u in enumerate(users):
        tok, last_code = "", None
        for _ in range(4):                     # retry transient non-200s
            tok = login_token(base, u["username"], u["password"], cfg,
                              consumer_headers(1000 + i), tout)
            last_code = "ok" if tok else "fail"
            if tok:
                break
            time.sleep(1.5)
        tokens[u["username"]] = tok
        bump("auth.login", last_code)
        if not tok:
            print(f"[auth]   ! no token for {u['username']} (last status {last_code})")
    ok = sum(1 for t in tokens.values() if t)
    print(f"[auth] obtained tokens for {ok}/{len(users)} known users")
    return tokens


# ── JWT crafting ─────────────────────────────────────────────────────────────
def b64url(obj: Any) -> str:
    raw = json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def make_jwt(identity: str, alg: str = "HS256", exp_delta: int = 120, sig: str = "fakesig") -> str:
    """Build a raw JWT shaped like flask_graphql_auth's tokens.

    DVGA's get_identity() decodes with verify_signature=False and reads the
    `identity` claim — so `identity` is the claim that matters here (not `sub`
    like VAmPI). The signature is never verified by DVGA; with alg="none" we
    emit an unsigned token, otherwise a bogus signature is appended.
    """
    header = {"alg": alg, "typ": "JWT"}
    now = int(time.time())
    payload = {"identity": identity, "fresh": True, "iat": now, "exp": now + exp_delta}
    token = f"{b64url(header)}.{b64url(payload)}"
    if alg == "none":
        return token + "."
    return f"{token}.{base64.urlsafe_b64encode(sig.encode()).rstrip(b'=').decode()}"


def token_claims(token: str) -> dict:
    """Base64url-decode a JWT's payload segment into a dict (no verification)."""
    try:
        seg = token.split(".")[1]
        seg += "=" * (-len(seg) % 4)
        obj = json.loads(base64.urlsafe_b64decode(seg))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def token_identity(token: str) -> Optional[str]:
    """The DVGA identity claim of a token (DVGA checks `identity`, not `sub`)."""
    claims = token_claims(token)
    return claims.get("identity") or claims.get("sub")


# ── run stats / formatting ───────────────────────────────────────────────────
stats: Dict[str, Dict[str, int]] = {}


def bump(key: str, code: Any) -> None:
    stats.setdefault(key, {})
    stats[key][code] = stats[key].get(code, 0) + 1


def fmt_dur(seconds: float) -> str:
    """Human-readable duration, e.g. '1h 03m 07s' / '4m 12s' / '9s'."""
    m, s = divmod(int(round(seconds)), 60)
    h, m = divmod(m, 60)
    if h:
        return f"{h}h {m:02d}m {s:02d}s"
    if m:
        return f"{m}m {s:02d}s"
    return f"{s}s"


def print_summary(timings: Dict[str, float], total: float) -> None:
    print("\n--- summary ---")
    for k in sorted(stats):
        print(f"{k}: {stats[k]}")
    print("\n--- timing ---")
    for phase, dur in timings.items():
        print(f"{phase}: {fmt_dur(dur)} ({dur:.1f}s)")
    print(f"total run time: {fmt_dur(total)} ({total:.1f}s)")
