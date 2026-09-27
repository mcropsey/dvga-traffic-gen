#!/usr/bin/env python3
"""
baseline_05_create_user.py — NORMAL baseline: create a user.

Runs `createUser(userData: {username, email, password})` with a fresh throwaway
account and a strong password. Teaches the baseline the expected createUser
mutation shape and its `{ user { id username } }` return.
Run: python3 baseline_05_create_user.py [--config path/to/dvga_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: create a user")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)

    username = dv.rand_username("norm")
    r = dv.graphql(base, """
      mutation($u: String!, $e: String!, $p: String!) {
        createUser(userData: {username: $u, email: $e, password: $p}) {
          user { id username }
        }
      }
    """, {"u": username, "e": dv.rand_email(username), "p": dv.rand_password()},
       cfg, dv.consumer_headers(5), tout)
    data = dv.gql_data(r)
    ok = dv.gql_ok(r)
    uid = (((data or {}).get("createUser") or {}).get("user") or {}).get("id")
    print(f"baseline_05 create_user: HTTP {r.status_code if r is not None else 'ERR'} -> "
          f"{'OK' if ok else 'FAILED'} id={uid} username={username!r}")


if __name__ == "__main__":
    main()
