#!/usr/bin/env python3
"""
baseline_06_login.py — NORMAL baseline: log in a known user.

Runs the `login(username, password)` mutation for a known lab user. Reports that
a token pair was issued (truncated) and decodes the access token's `identity`
claim + expiry so the baseline learns the token shape (DVGA access tokens are
short-lived — note the exp-iat delta).
Run: python3 baseline_06_login.py [--config path/to/dvga_config.yaml]
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
    ap = argparse.ArgumentParser(description="NORMAL baseline: login a known user")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)
    u = dv.known_users(cfg)[0]

    tok = dv.login(base, u["username"], u["password"], cfg, dv.consumer_headers(6), tout)
    if not tok:
        print(f"baseline_06 login: FAILED for {u['username']}")
        return
    token = tok["access_token"]
    claims = dv.token_claims(token)
    delta = claims.get("exp", 0) - claims.get("iat", 0)
    print(f"baseline_06 login: OK for {u['username']} -> token {token[:24]}... "
          f"identity={claims.get('identity')} exp-iat={delta}s")


if __name__ == "__main__":
    main()
