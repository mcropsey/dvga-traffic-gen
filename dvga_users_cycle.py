#!/usr/bin/env python3
"""
Generate NORMAL traffic for DVGA user-management flows.

DVGA is a GraphQL app: everything goes through POST /graphql, and the
authenticated identity is carried by the `me(token:)` query argument (DVGA
does not use an Authorization header).

Flow per user (repeated for N cycles):
  1. Login (mutation login -> access_token)
  2. View own profile (query me(token))
  3. List all users (query users)
  4. View own record (query users(id))
  5. Search own username (query search(keyword))
  6. Discard token

This teaches an API security solution the expected behaviour when users manage
their own account. Only the caller's OWN resources are touched (no BOLA).

NOTE: DVGA issues short-lived JWTs (120 s access / 30 s refresh); the script
re-logins once per user per cycle, and the per-user flow is a few quick calls.
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dvga_common as dv


def find_config():
    if os.path.exists("dvga_config.yaml"):
        return "dvga_config.yaml"
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dvga_config.yaml")


def view_me(cfg, base, token, hdrs, tout):
    """me(token) — own profile."""
    r = dv.graphql(base, 'query { me(token: "%s") { id username } }' % token,
                   None, cfg, hdrs, tout)
    data = dv.gql_data(r)
    if data and "me" in data:
        return data["me"]
    return None


def list_users(cfg, base, hdrs, tout):
    """users — list all users (basic info, no password field)."""
    r = dv.graphql(base, "query { users { id username } }", None, cfg, hdrs, tout)
    data = dv.gql_data(r)
    if data and isinstance(data.get("users"), list):
        return data["users"]
    return []


def get_own_user(cfg, base, user_id, hdrs, tout):
    """users(id) — own record by id."""
    r = dv.graphql(base, "query { users(id: %s) { id username } }" % user_id,
                   None, cfg, hdrs, tout)
    data = dv.gql_data(r)
    if data and isinstance(data.get("users"), list) and data["users"]:
        return data["users"][0]
    return None


def search_username(cfg, base, keyword, hdrs, tout):
    """search(keyword) — search for a username."""
    r = dv.graphql(base, """
      query { search(keyword: "%s") { ... on UserObject { id username } } }
    """ % keyword, None, cfg, hdrs, tout)
    data = dv.gql_data(r)
    if data and isinstance(data.get("search"), list):
        return data["search"]
    return []


def main():
    parser = argparse.ArgumentParser(
        description="Generate normal (legitimate) user-management traffic for DVGA")
    parser.add_argument("--config", default=find_config(),
                        help="Path to config file (default: dvga_config.yaml)")
    parser.add_argument("--cycles", type=int, default=1,
                        help="Number of full cycles through all known users (default: 1)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay (seconds) between major steps (default: 0.5)")
    parser.add_argument("--timeout", type=float, default=12.0,
                        help="HTTP timeout in seconds (default: 12)")
    args = parser.parse_args()

    cfg = dv.load_config(str(args.config))
    base = dv.base_url(cfg)
    tout = args.timeout
    users = dv.known_users(cfg)

    print(f"Target  : {base} (graphql at {dv.graphql_path(cfg)})")
    print(f"Users   : {len(users)}")
    print(f"Cycles  : {args.cycles}")
    print(f"Purpose : NORMAL traffic only (own profile, list users, own record, search)")
    print("-" * 60)

    for cycle in range(1, args.cycles + 1):
        print(f"\n=== Cycle {cycle}/{args.cycles} ===")
        for idx, u in enumerate(users):
            username = u["username"]
            hdrs = dv.consumer_headers(idx)
            print(f"\nUser: {username}")

            # 1. Login (fresh token each turn — tokens are short-lived)
            tok = dv.login_token(base, username, u["password"], cfg, hdrs, tout)
            if not tok:
                print("  Skipping (login failed)")
                continue
            time.sleep(args.delay * 0.4)

            # 2. View own profile
            me = view_me(cfg, base, tok, hdrs, tout)
            print(f"  Own profile: {me.get('username') if me else None}")
            time.sleep(args.delay * 0.3)

            # 3. List all users
            all_users = list_users(cfg, base, hdrs, tout)
            print(f"  Listed {len(all_users)} users")
            time.sleep(args.delay * 0.3)

            # 4. View own record (by id, if we have one)
            own_id = me.get("id") if me else None
            if own_id is not None:
                own = get_own_user(cfg, base, own_id, hdrs, tout)
                print(f"  Own record: {own.get('username') if own else None}")
            else:
                print("  (no own id — skipping own-record read)")
            time.sleep(args.delay * 0.3)

            # 5. Search own username
            hits = search_username(cfg, base, username, hdrs, tout)
            print(f"  Search '{username}' -> {len(hits)} hit(s)")

            # 6. Discard token (JWT — just drop it)
            time.sleep(args.delay)

    print("\nDone — normal user-management traffic generated.")


if __name__ == "__main__":
    main()
