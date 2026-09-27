#!/usr/bin/env python3
"""
baseline_09_edit_paste.py — NORMAL baseline: edit own paste.

Creates a paste (so we own one), then runs `editPaste(id, title, content)` to
update it. Teaches the baseline the expected editPaste mutation shape and its
`{ paste { id title } }` return. Only the caller's OWN paste is edited (no BOLA).
Run: python3 baseline_09_edit_paste.py [--config path/to/dvga_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: edit own paste")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)
    hdrs = dv.consumer_headers(9)

    # Create a paste we own, so the edit targets our own resource.
    title = dv.rand_paste_title("norm")
    r0 = dv.graphql(base, """
      mutation($t: String!, $c: String!) {
        createPaste(title: $t, content: $c, public: true, burn: false) { paste { id title } }
      }
    """, {"t": title, "c": "v1"}, cfg, hdrs, tout)
    data0 = dv.gql_data(r0)
    pid = (((data0 or {}).get("createPaste") or {}).get("paste") or {}).get("id")
    if pid is None:
        print("baseline_09 edit_paste: FAILED (could not create a paste to edit)")
        return

    r = dv.graphql(base, """
      mutation($id: Int, $t: String, $c: String) {
        editPaste(id: $id, title: $t, content: $c) { paste { id title } }
      }
    """, {"id": int(pid) if str(pid).isdigit() else 1, "t": title + " v2", "c": "updated"},
       cfg, hdrs, tout)
    data = dv.gql_data(r)
    ok = dv.gql_ok(r)
    edited = (((data or {}).get("editPaste") or {}).get("paste") or {}).get("id")
    print(f"baseline_09 edit_paste: HTTP {r.status_code if r is not None else 'ERR'} -> "
          f"{'OK' if ok else 'FAILED'} edited_id={edited}")


if __name__ == "__main__":
    main()
