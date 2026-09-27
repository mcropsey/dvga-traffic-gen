#!/usr/bin/env python3
"""
baseline_02_list_pastes.py — NORMAL baseline: list public pastes.

Runs `pastes(public: true)` (public). Returns the list of public pastes.
Teaches the baseline the expected shape of the paste-listing query.
Run: python3 baseline_02_list_pastes.py [--config path/to/dvga_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: list public pastes")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)

    r = dv.graphql(base, "query { pastes(public: true) { id title public } }",
                   None, cfg, dv.consumer_headers(2), tout)
    data = dv.gql_data(r)
    ok = dv.gql_ok(r)
    pastes = (data or {}).get("pastes", []) if data else []
    print(f"baseline_02 list_pastes: HTTP {r.status_code if r is not None else 'ERR'} -> "
          f"{'OK' if ok else 'FAILED'} count={len(pastes)}")


if __name__ == "__main__":
    main()
