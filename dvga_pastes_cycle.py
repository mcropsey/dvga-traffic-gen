#!/usr/bin/env python3
"""
Generate NORMAL traffic for DVGA paste-management flows.

DVGA is a GraphQL app: everything goes through POST /graphql.

Flow per paste (repeated for N cycles):
  1. List public pastes (query pastes)
  2. Create a paste (mutation createPaste)
  3. Read own paste (query paste(id))
  4. Edit own paste (mutation editPaste)
  5. Search own paste (query search(keyword))
  6. Discard (delete own paste with deletePaste(id) to keep state clean)

This teaches an API security solution the expected behaviour when a user works
with their OWN pastes (create -> read -> edit -> search -> delete). Only the
caller's OWN paste is touched (no BOLA).
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


def list_pastes(cfg, base, hdrs, tout):
    r = dv.graphql(base, "query { pastes(public: true) { id title public } }",
                   None, cfg, hdrs, tout)
    data = dv.gql_data(r)
    if data and isinstance(data.get("pastes"), list):
        return data["pastes"]
    return []


def create_paste(cfg, base, title, content, hdrs, tout):
    r = dv.graphql(base, """
      mutation($t: String!, $c: String!) {
        createPaste(title: $t, content: $c, public: true, burn: false) {
          paste { id title content public }
        }
      }
    """, {"t": title, "c": content}, cfg, hdrs, tout)
    data = dv.gql_data(r)
    if data and isinstance(data.get("createPaste"), dict):
        return data["createPaste"].get("paste")
    return None


def get_paste(cfg, base, pid, hdrs, tout):
    r = dv.graphql(base, "query { paste(id: %s) { id title content } }" % pid,
                   None, cfg, hdrs, tout)
    data = dv.gql_data(r)
    if data and isinstance(data.get("paste"), dict):
        return data["paste"]
    return None


def edit_paste(cfg, base, pid, title, content, hdrs, tout):
    r = dv.graphql(base, """
      mutation($id: Int, $t: String, $c: String) {
        editPaste(id: $id, title: $t, content: $c) { paste { id title } }
      }
    """, {"id": pid, "t": title, "c": content}, cfg, hdrs, tout)
    return r


def search_paste(cfg, base, keyword, hdrs, tout):
    r = dv.graphql(base, """
      query { search(keyword: "%s") { ... on PasteObject { id title } } }
    """ % keyword, None, cfg, hdrs, tout)
    data = dv.gql_data(r)
    if data and isinstance(data.get("search"), list):
        return data["search"]
    return []


def delete_paste(cfg, base, pid, hdrs, tout):
    r = dv.graphql(base, "mutation { deletePaste(id: %s) { result } }" % pid,
                   None, cfg, hdrs, tout)
    data = dv.gql_data(r)
    if data and isinstance(data.get("deletePaste"), dict):
        return data["deletePaste"].get("result")
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Generate normal (legitimate) paste-management traffic for DVGA")
    parser.add_argument("--config", default=find_config(),
                        help="Path to config file (default: dvga_config.yaml)")
    parser.add_argument("--cycles", type=int, default=1,
                        help="Number of full paste cycles (default: 1)")
    parser.add_argument("--delay", type=float, default=0.5,
                        help="Delay (seconds) between major steps (default: 0.5)")
    parser.add_argument("--timeout", type=float, default=12.0,
                        help="HTTP timeout in seconds (default: 12)")
    args = parser.parse_args()

    cfg = dv.load_config(str(args.config))
    base = dv.base_url(cfg)
    tout = args.timeout
    users = dv.known_users(cfg)
    actor = users[0]["username"] if users else "operator"

    print(f"Target  : {base} (graphql at {dv.graphql_path(cfg)})")
    print(f"Actor   : {actor}")
    print(f"Cycles  : {args.cycles}")
    print(f"Purpose : NORMAL traffic only (list, create, read, edit, search, delete OWN paste)")
    print("-" * 60)

    for cycle in range(1, args.cycles + 1):
        print(f"\n=== Cycle {cycle}/{args.cycles} ===")
        hdrs = dv.consumer_headers(cycle)

        # 1. List public pastes
        pastes = list_pastes(cfg, base, hdrs, tout)
        print(f"  Listed {len(pastes)} public pastes")
        time.sleep(args.delay * 0.3)

        # 2. Create a paste
        title = dv.rand_paste_title(f"norm{cycle}")
        paste = create_paste(cfg, base, title, dv.rand_password(), hdrs, tout)
        pid = paste.get("id") if paste else None
        print(f"  Created paste: {pid}")
        if pid is None:
            print("  Skipping rest (create failed)")
            continue
        time.sleep(args.delay * 0.3)

        # 3. Read own paste
        own = get_paste(cfg, base, pid, hdrs, tout)
        print(f"  Read own paste: {own.get('title') if own else None}")
        time.sleep(args.delay * 0.3)

        # 4. Edit own paste
        r = edit_paste(cfg, base, pid, title + " v2", "updated content", hdrs, tout)
        print(f"  Edited own paste -> HTTP {r.status_code if r is not None else 'err'}")
        time.sleep(args.delay * 0.3)

        # 5. Search own paste
        hits = search_paste(cfg, base, title, hdrs, tout)
        print(f"  Search '{title}' -> {len(hits)} hit(s)")
        time.sleep(args.delay * 0.3)

        # 6. Delete own paste (keep lab state clean)
        res = delete_paste(cfg, base, pid, hdrs, tout)
        print(f"  Deleted own paste -> result={res}")
        time.sleep(args.delay)

    print("\nDone — normal paste-management traffic generated.")


if __name__ == "__main__":
    main()
