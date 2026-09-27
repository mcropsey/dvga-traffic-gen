#!/usr/bin/env python3
"""
baseline_04_get_paste.py — NORMAL baseline: read a single paste by id.

Runs `paste(id:)`. First ensures a paste exists (creates one if id 1 is absent),
then reads it back. Teaches the baseline the expected single-paste read shape.
Run: python3 baseline_04_get_paste.py [--config path/to/dvga_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: read a paste by id")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)
    hdrs = dv.consumer_headers(4)

    # Ensure at least one paste exists (DVGA seeds some; id 1 is typical).
    r0 = dv.graphql(base, "query { paste(id: 1) { id title } }", None, cfg, hdrs, tout)
    if not dv.gql_ok(r0):
        dv.graphql(base, """
          mutation { createPaste(title: "seed", content: "seed", public: true, burn: false) { paste { id } } }
        """, None, cfg, hdrs, tout)

    r = dv.graphql(base, "query { paste(id: 1) { id title content public } }",
                   None, cfg, hdrs, tout)
    data = dv.gql_data(r)
    ok = dv.gql_ok(r)
    paste = (data or {}).get("paste")
    pid = paste.get("id") if paste else None
    ptitle = paste.get("title") if paste else None
    print(f"baseline_04 get_paste: HTTP {r.status_code if r is not None else 'ERR'} -> "
          f"{'OK' if ok else 'FAILED'} id={pid} title={ptitle!r}")


if __name__ == "__main__":
    main()
