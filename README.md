# Sentinel Monitor Dashboard

Security posture, metrics, vulnerability counters and audit telemetry for a
per-user secrets vault. Monorepo:

- **backend/** — Django 6.1 + django-ninja 1.7 (SQLite dev / PostgreSQL in
  prod — see Configuration; JWT via django-ninja-jwt, rate limiting,
  structured logging, pytest)
- **frontend/** — Vue 3 + Vite + Pinia + vue-router + axios + Tailwind CSS v4

## Quick start

### Backend (http://localhost:8000)

```powershell
cd backend
.venv\Scripts\Activate.ps1        # python 3.13 venv already has Django
pip install -r requirements.txt   # idempotent; pins are recorded there
python manage.py migrate
python manage.py createsuperuser  # or reuse the bootstrapped admin
python manage.py runserver
```

Interactive OpenAPI docs: http://localhost:8000/api/v1/docs

The repo root carries a thin `requirements.txt` forwarding to
`backend/requirements.txt`, so `pip install -r requirements.txt` works from
either directory — edit pins in `backend/requirements.txt` only.

### Frontend (http://localhost:5173)

```powershell
cd frontend
npm install
npm run dev   # /api is proxied to :8000 (vite.config.js)
npm run build # production bundle -> dist/
```

Sign in with your Django superuser credentials, or create an account from /register.

### Parallel checkouts (`git worktree`)

Exercise another branch (e.g. the benchmark target below) without disturbing
this checkout:

```powershell
git worktree add ../demo-start -b demo-start origin/demo-start
New-Item -ItemType Junction -Path ../demo-start/backend/.venv -Target (Resolve-Path backend/.venv).Path
```

The sibling directory shares this repository's history but has its own
working files, so commits on its branch never touch this checkout. The
`backend/.venv` junction reuses this interpreter (no second `pip install`);
untracked files such as `backend/.env` and `db.sqlite3` do not travel between
worktrees. (The branch already exists locally? Re-attach with
`git worktree add ../demo-start demo-start`.) `--root` scopes the source-file
rules to the sibling tree — see Security Metrics for its exact reach.

### Bob 2.0 benchmark target (`demo-start`)

`main` is the "after" reference: the scanner plus the clean implementation.
`demo-start` is the "before" state: the same code with exactly one deliberate
regression per scanner rule (its `demo(flaws): seed the seven deliberate
regressions...` commit). Bob fixes the flaws in the **working tree only** —
fixes are never committed, and each session is wiped with `git restore .`
before the next attempt, so every attempt starts from the identical flawed
baseline. The branch is never merged back to `main`.

Scoring runs from **inside** `demo-start`: the source-side rules read its
files while the registry rules and the N+1 probe introspect its live Django
process, so all seven rule classes measure the flawed app itself (a `--root`
sweep from `main` would only cover the source-side family). The harness in
`benchmark/` wraps one attempt:

```powershell
benchmark/run.ps1 bob-attempt-1     # score; exit 1 while criticals remain
cd ../demo-start; git restore .     # wipe the attempt before the next round
```

#### 🎯 Sending the seven-flaws prompt to Bob

First attempt starts here. Working from inside `demo-start/` (the sibling
worktree from above), paste the prompt below into Bob 2.0's chat and let him
execute the plan against the tree. Bob edits files but never commits, and
`git restore .` wipes each attempt, so every run starts from the identical
flawed baseline. The harness loop is documented in `benchmark/README.md`.

**Prompt — copy verbatim:**

```text
Refactor and secure the entire Django Ninja codebase to enterprise production
standards. Please execute the following multi-agent remediation plan:

1. Security hardening
   - Eliminate the raw-SQL injection vulnerability in the search route by
     replacing cursor execution or any hand-built queries with safe Django
     ORM queries.
   - Secure all administrative and delete endpoints with proper
     authentication headers.
2. Configuration hygiene
   - Extract all hardcoded secret strings into secure environment-variable
     calls.
3. Performance and type-safety
   - Fix the N+1 database query bottleneck in the list endpoints using
     select_related() and replace any raw unvalidated dictionaries or
     payloads with strongly typed Django Ninja schemas.
4. Resilience
   - Implement robust request rate-limiting on sensitive login and
     data-heavy routes.
5. Test automation
   - Generate a comprehensive, passing pytest suite inside a dedicated
     tests/ directory covering all API success paths and error states.
6. Missing authentication
   - Fix any routers that accept anonymous audit exports.
7. Missing Pydantic validation
   - Create a valid body schema for payloads accepted by mutating handlers.
```

When Bob reports done, score and wipe exactly as above; repeat until
`security_scan` reports `0 finding(s)`.

Scored runs append to demo-start's own scan history (`ScanRun` rows in its
`backend/db.sqlite3`), so `manage.py security_scan` — or a dashboard served
from `demo-start/backend` — shows the 7 -> 0 trend. Details:
`benchmark/README.md`.

### Reproducing the benchmark on a fresh machine

Prerequisites: Git and Python 3.13.

```powershell
git clone https://github.com/Malu2555/Plethora-and-Bob-2.0.git
cd Plethora-and-Bob-2.0
python -m venv backend/.venv                        # or: py -3.13 -m venv backend/.venv
backend\.venv\Scripts\pip install -r requirements.txt
backend\.venv\Scripts\python.exe backend\manage.py migrate

git worktree add ../demo-start -b demo-start origin/demo-start
New-Item -ItemType Junction -Path ../demo-start/backend/.venv -Target (Resolve-Path backend/.venv).Path

cd ../demo-start/backend
.venv\Scripts\python.exe manage.py migrate          # demo-start keeps its own DB
.venv\Scripts\python.exe manage.py security_scan    # expect 7 findings, exit 1
```

On macOS / Linux the venv lives at `backend/.venv/bin/python`; junctions are
Windows-only, so give `demo-start` its own venv there
(`python3.13 -m venv backend/.venv`). `benchmark/run.sh` covers the path
differences for the scoring loop.

## API surface (all under /api/v1)

| Method | Path                  | Success | Errors                         |
|--------|-----------------------|---------|--------------------------------|
| POST   | /auth/token           | 200     | 401 bad creds, 422, 429 (30/m) |
| POST   | /auth/refresh         | 200     | 401 invalid refresh token      |
| POST   | /auth/register        | 201     | 409 taken user/email, 422, 429 (12/m per IP) |
| GET    | /vault/               | 200     | 401 (no/invalid JWT)           |
| POST   | /vault/               | 201*    | 401, 422, 429 (120/m per user) |
| GET    | /vault/{id}           | 200     | 401, 404 (IDOR-safe)           |
| PATCH  | /vault/{id}           | 200     | 401, 404, 422                  |
| DELETE | /vault/{id}           | 204     | 401, 404                       |
| GET    | /audit/               | 200**   | 401                            |
| GET    | /security/posture     | 200     | 401                            |
| GET    | /security/findings    | 200     | 401                            |
| GET    | /security/scan/runs   | 200     | 401                            |
| POST   | /security/scan        | 202     | 401, 409 (scan already running), 422 (unknown rule), 429 (12/m per user) |

\* 201 includes a Location header.
\*\* pagination envelope {items, count} with ?limit=&offset=.

Status-code contract: 200/201/204 success, 401 automatic via JWTAuth, 404
(never 403) for cross-user access to avoid resource enumeration, 409 for
account-creation collisions (anti-enumeration) or a second concurrent scan,
422 for schema violations, 429 with Retry-After when throttled.

Posture formula (v2): `max(0, 100 - findings_deduction - 25*critical - 15*high)`.
The audit terms count the last 24h of telemetry rows; `findings_deduction`
is the weight-sum over the LATEST scanner run, capped at 80 — see the
Security Metrics section below. `medium`/`low` remain reserved.

## Security Metrics (scanner)

A dashboard-driven vulnerability scanner snapshots the checkout tree for
seven vulnerability classes. Run it from the CLI
(`python manage.py security_scan`, see `--help` for `--rule`, `--dry-run`,
`--root`, `--no-runtime-probe`, `--no-collect-tests`; exit code 1 =
critical findings, ready for CI gating) or from the dashboard via POST
/security/scan — the "Findings" page shows run history, per-rule totals, and
a drill-down panel. `--root` points the source-side rules (raw_sql,
hardcoded_secret, absent_tests) at another checkout — e.g. a sibling
worktree — with the branch label defaulting to the target directory name;
registry rules and the N+1 probe always introspect the running Django
process.

| Rule                 | Weight | Severity | What it flags                                                      |
|----------------------|--------|----------|--------------------------------------------------------------------|
| raw_sql              | 25     | critical | string-built SQL / raw query primitives in backend source          |
| missing_auth         | 25     | critical | routes with no effective authenticator (credential routes exempt)  |
| hardcoded_secret     | 25     | critical | credential-shaped literals in source/config (values redacted)      |
| missing_rate_limit   | 15     | high     | mutating endpoints without a throttle (GET reads exempt)           |
| absent_tests         | 15     | high     | missing test suite, or a suite that cannot be collected            |
| n_plus_one           | 10     | warning  | runtime probe: per-row query fan-out on populated list routes      |
| missing_pydantic     | 10     | warning  | mutating handlers without a pydantic body model                    |

Key behaviors:

- **Two streams, never mixed.** `AuditLog` stays runtime-facts-only; scanner
  output lands in dedicated `ScanRun` + `Finding` tables. The posture score
  attributes each deduction separately (`100 - findings - audit`).
- **Idempotent runs.** Findings are keyed by a
  `sha256(rule|file|line)` fingerprint and UPSERTed; re-running a scan
  never duplicates rows. History is append-only per run.
- **Live registry, clean rules.** Rules introspect the mounted ninja routers
  (auth/throttle/body models) instead of grepping decorators, so the audit
  is canonical. The clean tree scans to exactly **zero** findings — any
  false positive is a test failure, not a dashboard surprise.
- **Zero-trace probes.** The N+1 runtime probe populates a throwaway user
  and records inside a rollback-only transaction; nothing survives.
- **Observational only.** The dashboard offers prose-only guidance ("why
  this matters" + "recommended direction"). It never edits files, never
  patches code, and never suggests snippets — fixes stay the maintainer's.

Rule metadata (labels, weights, severity, prose) lives in
`backend/security/weights.py`; adding a rule means extending that registry,
a `backend/security/rules/*` module, and nothing else.

## Testing

```powershell
cd backend
python -m pytest        # 83 tests: CRUD + auth + register + IDOR + throttle + audit + posture + scanner
python manage.py check  # django system check (no issues)
python manage.py security_scan   # 0 findings on a clean tree (CI-gate exit code)
```

All state-changing paths emit audit rows via signals; core modules assert
zero raw SQL (tests/test_no_raw_sql.py).

## Configuration (env-first, dev fallbacks)

Secrets and flags live in `backend/.env` (gitignored — real values come from
the environment in prod, which always wins). Copy `backend/.env.example` to
start. Variables: `SENTINEL_SECRET_KEY`, `SENTINEL_DEBUG`,
`SENTINEL_ALLOWED_HOSTS`, `SENTINEL_CORS_ORIGINS`.

Database engine switch — `SENTINEL_DB_ENGINE`:
- `sqlite` (default) → `backend/db.sqlite3` — dev + tests, zero config
- `postgresql` → psycopg 3 with creds from `SENTINEL_DB_NAME` / `_USER` /
  `_PASSWORD` / `_HOST` / `_PORT`, persistent pooled connections
  (`CONN_MAX_AGE`, health checks) for production

The backend boots with dev fallbacks even when no `.env` file is present.

## Layout

```
backend/
  monitor/            settings, root URLconf, JWT endpoints (auth_api.py)
  vault/              VaultRecord model + CRUD router + pydantic schemas
  auditlog/           AuditLog model + post_save/post_delete signals + feed API
  security/           posture aggregate endpoint + scanner (models, weights,
                      rules/, API endpoints, management command)
  tests/              pytest suite (conftest + 9 test modules)
  logs/sentinel.log   rotating structured log (console + file)
frontend/
  src/utils/          logger (level-filtered), session, jwt, toast
  src/services/api.js axios + interceptor (silent refresh, 4xx/429 toasts)
  src/stores/auth.js  Pinia auth store
  src/components/     AppShell, PostureScoreGauge, AuditTelemetryTiles,
                      SecurityFindingsTiles, MetricsTiles, AuditLogFeed, VaultList
  src/views/          LoginPage, DashboardPage, SecurityPage, VaultPage, AuditPage
benchmark/            Bob 2.0 scoring harness (run.sh / run.ps1) + its README
```