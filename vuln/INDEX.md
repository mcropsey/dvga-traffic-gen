# DVGA — Vuln / Challenge Scripts

Detection-pattern scripts for a **Damn Vulnerable GraphQL Application** (DVGA)
lab instance. Each script exercises ONE attack pattern (introspection, SQLi,
OS command injection, JWT forgery, SSRF, BOLA, …) so an API-security sensor
can be validated against it.

DVGA is a GraphQL app: every pattern below is a single `POST /graphql`
(batches allowed) or a `GET` on one of the app's HTML endpoints — unlike VAmPI
which is a REST API.

> **Scope:** DVGA is a deliberately vulnerable training app. Point
> `dvga_config.yaml -> target.base_url` at **your own lab only** — never at a
> system you don't own. DVGA listens on **port 5013** by default
> (`config.py WEB_PORT=5013`, docker `-p 5013:5013`).
>
> **Difficulty modes:** DVGA ships in **Beginner (easy)** mode by default — all
> protections off, every vulnerability exploitable. Switching to **Expert
> (hard)** mode (`GET /difficulty/hard` or `X-DVGA-MODE: Expert`) enables the
> Depth/Cost/OpName/DenyList/Introspection middlewares. These scripts report
> what actually happened, so they work in either mode — just expect `[ok]`
> where a hard-mode middleware blocks the pattern.

## Scripts

| Script | Pattern (DVGA scenario) | Endpoint / field |
|--------|-------------------------|------------------|
| `dvga_challenge_01_introspection.py` | GraphQL Introspection | `__schema` query |
| `dvga_challenge_02_graphiql.py` | GraphiQL Interface | `GET /graphiql`, `GET /` |
| `dvga_challenge_03_sql_injection.py` | SQL Injection | `pastes(filter:)` |
| `dvga_challenge_04_os_command_injection.py` | OS Command Injection #1/#2 | `systemDebug(arg)`, `systemDiagnostics(cmd)` |
| `dvga_challenge_05_jwt_forgery.py` | GraphQL JWT Token Forge | `me(token:)` |
| `dvga_challenge_06_stored_xss.py` | Stored Cross-Site Scripting | `createPaste(content:)` |
| `dvga_challenge_07_ssrf.py` | Server-Side Request Forgery | `importPaste(host:)` |
| `dvga_challenge_08_path_traversal.py` | Arbitrary File Write / Path Traversal | `uploadPaste(filename:)` |
| `dvga_challenge_09_batch_query_dos.py` | Batch Query Attack (DoS) | `POST /graphql` (JSON array) |
| `dvga_challenge_10_deep_recursion.py` | Deep Recursion Query Attack (DoS) | `pastes{owner{paste{…}}}` |
| `dvga_challenge_11_weak_password.py` | Weak Password Protection | `login(username,password)` |
| `dvga_challenge_12_bola_pastes.py` | Broken Object Level Access (pastes) | `editPaste(id:)`, `paste(id:)` |

## Run

```bash
# from the dvga-traffic-gen/ directory
python3 vuln/dvga_challenge_01_introspection.py
python3 vuln/dvga_challenge_02_graphiql.py
# ...
python3 vuln/dvga_challenge_11_weak_password.py
python3 vuln/dvga_challenge_12_bola_pastes.py
```

Each reads `dvga_config.yaml` (falling back to the repo-root one) and prints
the outcome + whether the pattern appears to have succeeded. Exit code is 0
even when a pattern "succeeds" — these are diagnostic, not assertions.

## Notes

- The scripts only **demonstrate** the pattern; they don't attempt to fully
  exploit beyond the single probe shown.
- `dvga_challenge_01`, `_06`, `_11` deliberately do **not** print secret
  values (full schema body / stored payloads / cracked passwords are flagged by
  presence, not dumped).
- `dvga_challenge_04` uses harmless commands (`whoami` / `id` / `echo` marker)
  and prints only the relevant fragment, not the full process table.
- `dvga_challenge_12` creates a **throwaway** victim paste so re-running never
  damages the seeded lab data.
- On a hard-mode instance the protected patterns (introspection, deep
  recursion, batch amplification, GraphiQL) are correctly blocked by DVGA's
  middlewares — the scripts report that honestly rather than forcing a
  "finding".

## DVGA source of truth

- Repo: `https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application`
- Schema + resolvers: `core/views.py`, `core/models.py`
- Auth / JWT: `core/helpers.py -> get_identity()` (`verify_signature: False`)
- Protection middlewares: `core/middleware.py`
- Seeded users: `setup.py` → `admin/changeme`, `operator/password123`
