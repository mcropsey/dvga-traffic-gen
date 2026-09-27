# DVGA Lab Traffic Generator

Generates API traffic against a **Damn Vulnerable GraphQL Application** (DVGA)
training instance to (1) advance the API through your security sensor's
*learning period* and (2) exercise the specific detection patterns that show up
as findings.

> DVGA is a deliberately vulnerable GraphQL app built for security training.
> Point this tool at **your own lab only** — never at systems you don't own.
>
> DVGA is a **GraphQL** app (one `POST /graphql` endpoint, batches allowed),
> not a REST API like VAmPI. Auth is via the `me(token:)` GraphQL argument
> (not an `Authorization` header), and DVGA's `get_identity()` decodes JWTs
> with `verify_signature: False` — so the `identity` claim is trusted and JWT
> forgery is a first-class finding.

## Files

| File | Purpose |
|------|---------|
| `dvga_traffic.py` | The main traffic generator (warmup + findings). |
| `dvga_common.py` | Shared helpers (config, GraphQL transport, login, JWT forging, consumers, stats). |
| `dvga_config.yaml` | All options live here — edit this, not the scripts. |
| `dvga_users_cycle.py` | Normal account-cycle traffic (create user, login, `me`, user list). |
| `dvga_pastes_cycle.py` | Normal paste-cycle traffic (list, create, read, edit, search). |
| `dvga_discovery.py` | Recon: introspection, endpoint probes, live operation exercise. |
| `dvga_attack.py` | One-shot runtime-alert trigger (exercises the whole vuln catalogue). |
| `baseline/` | 10 "normal" training scripts (one behavior each). |
| `vuln/` | 12 detection-pattern scripts (introspection, SQLi, OS-cmd-inj, JWT forge, …). |
| `run_cycle_scripts_hourly.sh` | Hourly runner for the cycle scripts. |
| `run_baseline_hourly.sh` | Hourly runner for the baseline scripts. |
| `requirements.txt` | Python dependencies. |
| `dvga_schema.graphql` | The DVGA GraphQL schema (reference for the operations). |
| `README.md` | This file. |

## Prerequisites

- Python 3.8 or newer (`python3 --version` to check).
- Network access from your machine to the DVGA instance (default **port 5013**).

## Setup (virtual environment)

Working in a virtual environment keeps these dependencies isolated from your
system Python. From the project folder:

```bash
# 1. create the venv
python3 -m venv .venv

# 2. activate it
source .venv/bin/activate

# 3. install dependencies into the venv
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
```

Once activated, your prompt shows `(.venv)`. To leave it later, run
`deactivate`.

## Configure

Open `dvga_config.yaml` and set the things specific to your lab:

```yaml
target:
  base_url: "http://localhost:5013"     # <- your DVGA instance (default port 5013)
  graphql_path: "/graphql"

known_users:
  users:
    - username: admin
      password: changeme
      email: admin@blackhatgraphql.com
    - username: operator
      password: password123
      email: operator@blackhatgraphql.com
```

Every script reads these same values, so set them once. Every option in the
file has an inline comment explaining exactly what changes when you edit it
(which phases run, consumer volume, credential-attempt volume, timeouts, etc.).
Review them before your first run.

> **Difficulty modes:** DVGA starts in **Beginner (easy)** mode — all
> protections off, every vulnerability exploitable. `GET /difficulty/hard`
> (or the `X-DVGA-MODE: Expert` header) enables the Depth/Cost/OpName/DenyList/
> Introspection middlewares. The scripts work in either mode and report what
> actually happened.

## Run

### Main generator (warmup + findings)

```bash
python3 dvga_traffic.py
```

That reads `dvga_config.yaml` from the current folder. To use a different
config file:

```bash
python3 dvga_traffic.py --config staging.yaml
```

Driven by the `run:` switches in the config:

- **warmup** — many distinct-consumer journeys (create user → login → paste
  CRUD) to build the observed-consumer count and move the API out of learning.
- **findings** — labeled populations: *authenticated* (valid sessions),
  *unauthenticated* (no token), and *bad-token* (forged / garbage tokens).

A typical first-day pattern is warmup-only (`run.findings: false`) to start the
learning clock, then flip to `run.findings: true` once the API reports out of
learning so the detection patterns actually surface.

### Cycle scripts (normal traffic, per area)

```bash
python3 dvga_users_cycle.py
python3 dvga_pastes_cycle.py
```

### Baseline scripts (normal behavior, one each)

```bash
# from the dvga-traffic-gen/ directory
python3 baseline/baseline_01_system_health.py
# ...
python3 baseline/baseline_10_search.py
```

### Vuln / challenge scripts (detection patterns)

```bash
# from the dvga-traffic-gen/ directory
python3 vuln/dvga_challenge_01_introspection.py
# ...
python3 vuln/dvga_challenge_12_bola_pastes.py
```

See `vuln/INDEX.md` for the full list and what each one exercises.

### One-shot runtime-alert trigger

```bash
python3 dvga_attack.py
```

Runs the whole DVGA vulnerability catalogue in one pass (introspection, data
exposure, SQLi, OS command injection, JWT forgery, stored XSS, SSRF, path
traversal, batch/recursion DoS, BOLA, weak password, rapid-fire). Use to
trigger a burst of runtime detections at once.

## Hourly runners

```bash
# install both (adjust the minute if you don't want the bottom-of-the-hour)
( crontab -l 2>/dev/null; echo "0 * * * * /home/mcropsey/dvga-traffic-gen/run_cycle_scripts_hourly.sh" ) | crontab -
( crontab -l 2>/dev/null; echo "0 * * * * /home/mcropsey/dvga-traffic-gen/run_baseline_hourly.sh" ) | crontab -
```

- `run_cycle_scripts_hourly.sh` → logs to `logs/dvga_cycle.log`
- `run_baseline_hourly.sh` → logs to `logs/dvga_baseline.log`

Both prefer the repo `.venv` if it exists, else fall back to system `python3`.

## Troubleshooting

- **`Missing dependency. Run: pip install pyyaml`** — the venv isn't active or
  deps aren't installed. Re-activate and run the `pip install -r requirements.txt`
  step. Confirm with `python3 -m pip list | grep -i pyyaml`.
- **`obtained tokens for 0/2 known users`** — the `known_users` list doesn't
  match the lab accounts. Fix them and re-run (DVGA seeds `admin/changeme` and
  `operator/password123`).
- **`NotOpenSSLWarning ... LibreSSL`** (yellow line on macOS) — harmless.
  Silence it by uncommenting `urllib3<2` in `requirements.txt` and reinstalling.
- **Connection errors / timeouts** — confirm `target.base_url` is reachable
  (`curl http://localhost:5013/`) and raise `http.timeout` if the lab is slow.
  DVGA defaults to **port 5013** — make sure the container/host is publishing
  that port (`docker run -p 5013:5013 ...`).

## Notes

- **Short-lived tokens.** DVGA issues JWTs that expire in ~120 s (access) /
  ~30 s (refresh). `dvga_common.py` re-logs in on demand, so you don't manage
  token refresh yourself.
- **Auth is an argument, not a header.** DVGA's `me(token:)` query takes the
  JWT as a GraphQL argument — the `Authorization` header is ignored by the app.
- **JWTs are unverified.** `core/helpers.py -> get_identity()` decodes with
  `verify_signature: False` and reads the `identity` claim — so a forged
  `alg=none` / weak-signature token with any `identity` is accepted. That's the
  `dvga_challenge_05` finding.
- Status codes printed in the run summary are DVGA's responses, **not** the
  sensor's verdict. Findings are raised by the monitoring platform after the
  learning period completes.
- Re-running is safe; warmup and the vuln scripts only create fresh throwaway
  users/pastes and don't disturb the known lab users.
- `vuln/dvga_challenge_01`, `_06`, `_11` deliberately do not print secret
  values (full schema / stored payloads / cracked passwords) — they only flag
  presence and count.
- The protected patterns (introspection, deep recursion, batch amplification,
  GraphiQL) are correctly blocked on an **Expert (hard)-mode** instance by
  DVGA's middlewares; the scripts report that honestly rather than forcing a
  "finding".

## DVGA source of truth

- Repo: `https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application`
- Schema + resolvers: `core/views.py`, `core/models.py`
- Auth / JWT: `core/helpers.py -> get_identity()`
- Protection middlewares: `core/middleware.py`
- Seeded users: `setup.py` → `admin/changeme`, `operator/password123`
