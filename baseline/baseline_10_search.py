#!/usr/bin/env python3
"""
baseline_10_search.py — NORMAL baseline: search users + pastes.

Runs `search(keyword:)` with a benign keyword and inline fragments over the
UserObject and PasteObject union. Teaches the baseline the expected search
query shape (the SearchResult interface).
Run: python3 baseline_10_search.py [--config path/to/dvga_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: search")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)

    r = dv.graphql(base, """
      query {
        search(keyword: "a") {
          ... on UserObject { id username }
          ... on PasteObject { id title }
        }
      }
    """, None, cfg, dv.consumer_headers(10), tout)
    data = dv.gql_data(r)
    ok = dv.gql_ok(r)
    hits = (data or {}).get("search", []) if data else []
    print(f"baseline_10 search: HTTP {r.status_code if r is not None else 'ERR'} -> "
          f"{'OK' if ok else 'FAILED'} hits={len(hits)}")


if __name__ == "__main__":
    main()
