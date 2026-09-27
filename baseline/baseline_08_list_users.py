#!/usr/bin/env python3
"""
baseline_08_list_users.py — NORMAL baseline: list users.

Runs `users { id username }` (public). Returns the roster of users by id and
username. Teaches the baseline the expected user-listing query shape (without
requesting the sensitive `password` field — that is a vuln pattern, not baseline).
Run: python3 baseline_08_list_users.py [--config path/to/dvga_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: list users")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)

    r = dv.graphql(base, "query { users { id username } }",
                   None, cfg, dv.consumer_headers(8), tout)
    data = dv.gql_data(r)
    ok = dv.gql_ok(r)
    users = (data or {}).get("users", []) if data else []
    print(f"baseline_08 list_users: HTTP {r.status_code if r is not None else 'ERR'} -> "
          f"{'OK' if ok else 'FAILED'} count={len(users)}")


if __name__ == "__main__":
    main()
