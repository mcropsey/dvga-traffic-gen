#!/usr/bin/env python3
"""
baseline_01_system_health.py — NORMAL baseline: query systemHealth.

Runs the `systemHealth` GraphQL query (public). Returns the app's system-load
string. Teaches the baseline the expected shape of the health query.
Run: python3 baseline_01_system_health.py [--config path/to/dvga_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: systemHealth query")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)

    r = dv.graphql(base, "query { systemHealth }", None, cfg, dv.consumer_headers(1), tout)
    data = dv.gql_data(r)
    ok = dv.gql_ok(r)
    val = (data or {}).get("systemHealth", "")
    print(f"baseline_01 system_health: HTTP {r.status_code if r is not None else 'ERR'} -> "
          f"{'OK' if ok else 'FAILED'} health={val[:60]!r}")


if __name__ == "__main__":
    main()
