#!/usr/bin/env python3
"""
baseline_03_create_paste.py — NORMAL baseline: create a paste.

Runs `createPaste(title, content, public: true, burn: false)` with a benign
title/content. Teaches the baseline the expected createPaste mutation shape and
its `{ paste { id title } }` return.
Run: python3 baseline_03_create_paste.py [--config path/to/dvga_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: create a paste")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)

    title = dv.rand_paste_title("norm")
    r = dv.graphql(base, """
      mutation($t: String!, $c: String!) {
        createPaste(title: $t, content: $c, public: true, burn: false) {
          paste { id title content public }
        }
      }
    """, {"t": title, "c": "normal baseline content"},
       cfg, dv.consumer_headers(3), tout)
    data = dv.gql_data(r)
    ok = dv.gql_ok(r)
    pid = (((data or {}).get("createPaste") or {}).get("paste") or {}).get("id")
    print(f"baseline_03 create_paste: HTTP {r.status_code if r is not None else 'ERR'} -> "
          f"{'OK' if ok else 'FAILED'} id={pid} title={title!r}")


if __name__ == "__main__":
    main()
