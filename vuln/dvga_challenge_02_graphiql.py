#!/usr/bin/env python3
"""
dvga_challenge_02_graphiql.py — GraphiQL interactive interface exposure.

DVGA serves a browser-based GraphQL IDE at GET /graphiql (and links to it from
the root page). Exposing GraphiQL in a lab/dev context is convenient; in
production it hands any visitor a ready-made console for the full schema.

We probe /graphiql (and the root page) and report whether an HTML IDE is
served. We do not dump the HTML.
Run: python3 dvga_challenge_02_graphiql.py [--config ...]
"""
import argparse
import os
import sys

import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dvga_common as dv


def find_config():
    if os.path.exists("dvga_config.yaml"):
        return "dvga_config.yaml"
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dvga_config.yaml")


def main():
    ap = argparse.ArgumentParser(description="GraphiQL interface exposure")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg).rstrip("/")
    tout = dv.timeout(cfg)

    exposed = False
    for path in ("/graphiql", "/"):
        try:
            r = requests.get(base + path, headers=dv.consumer_headers(802), timeout=tout, allow_redirects=True)
        except requests.RequestException as e:
            print(f"GET {path} -> error {e}")
            continue
        ct = r.headers.get("content-type", "")
        is_html = "html" in ct.lower()
        has_ide = ("graphiql" in (r.text or "").lower()) or ("graphiql" in ct.lower())
        if is_html and has_ide:
            exposed = True
        print(f"GET {path} -> HTTP {r.status_code} content-type={ct!r} graphiql={'yes' if has_ide else 'no'}")

    print()
    if exposed:
        print("[FINDING] GraphiQL / interactive GraphQL IDE is exposed — any visitor gets a "
              "ready-made query console for the full schema.")
    else:
        print("[ok] no GraphiQL IDE detected at probed paths.")


if __name__ == "__main__":
    main()
