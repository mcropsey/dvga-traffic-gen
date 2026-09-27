#!/usr/bin/env python3
"""
dvga_challenge_01_introspection.py — GraphQL Introspection (schema disclosure).

DVGA leaves introspection enabled, so a single `__schema` query returns the
entire schema: every Query/Mutation field, type, and argument. This is the
canonical "the schema is the attack surface" signal for GraphQL — anything a
sensor sees here is available to any unauthenticated client.

We dump the query/mutation root field names and count the total types, then
flag it. We do NOT print the full schema body (it is large and noisy).
Run: python3 dvga_challenge_01_introspection.py [--config ...]
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
    ap = argparse.ArgumentParser(description="GraphQL introspection (schema disclosure)")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)

    r = dv.graphql(base, """
      query {
        __schema {
          queryType  { name }
          mutationType { name }
          types { name kind fields { name } }
        }
      }
    """, None, cfg, dv.consumer_headers(801), tout)

    body = r.json() if r.headers.get("content-type", "").find("json") >= 0 else {}
    schema = (body.get("data") or {}).get("__schema")
    if schema is None:
        print("introspection -> blocked/absent (no __schema in response).")
        return

    qfields = [f["name"] for t in schema.get("types", []) if t.get("name") == schema.get("queryType", {}).get("name")
               for f in (t.get("fields") or [])]
    mfields = [f["name"] for t in schema.get("types", []) if t.get("name") == schema.get("mutationType", {}).get("name")
               for f in (t.get("fields") or [])]
    ntypes = len(schema.get("types", []))

    print(f"introspection -> ENABLED. types={ntypes}")
    print(f"  Query fields   ({len(qfields)}): {', '.join(sorted(qfields))}")
    print(f"  Mutation fields({len(mfields)}): {', '.join(sorted(mfields))}")
    print("\n[FINDING] Full GraphQL introspection is available unauthenticated — the entire "
          "attack surface (types, fields, args) is disclosed to any client.")


if __name__ == "__main__":
    main()
