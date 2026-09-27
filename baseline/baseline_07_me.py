#!/usr/bin/env python3
"""
baseline_07_me.py — NORMAL baseline: read own profile via me(token).

Logs in a known user, then runs `me(token: <access_token>) { id username }`.
Teaches the baseline the expected authenticated "who am I" shape (DVGA carries
the token as a GraphQL argument, not an Authorization header).
Run: python3 baseline_07_me.py [--config path/to/dvga_config.yaml]
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dvga_common as dv


def find_config():
    if os.path.exists("dvga_config.yaml"):
        return "dvga_config.yaml"
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dvga_config.yaml")


def main():
    ap = argparse.ArgumentParser(description="NORMAL baseline: me(token) own profile")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)
    u = dv.known_users(cfg)[0]
    hdrs = dv.consumer_headers(7)

    token = dv.login_token(base, u["username"], u["password"], cfg, hdrs, tout)
    if not token:
        print(f"baseline_07 me: FAILED (login for {u['username']})")
        return

    r = dv.graphql(base, 'query { me(token: "%s") { id username } }' % token,
                   None, cfg, hdrs, tout)
    data = dv.gql_data(r)
    ok = dv.gql_ok(r)
    me = (data or {}).get("me")
    mid = me.get("id") if me else None
    muser = me.get("username") if me else None
    print(f"baseline_07 me: HTTP {r.status_code if r is not None else 'ERR'} -> "
          f"{'OK' if ok else 'FAILED'} id={mid} username={muser!r}")


if __name__ == "__main__":
    main()
