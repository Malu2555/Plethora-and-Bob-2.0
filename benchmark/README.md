# Bob 2.0 benchmark harness

Scores one Bob 2.0 fix-session against the **`demo-start`** worktree -- the
frozen benchmark target that carries one deliberate regression per scanner
rule (see its `demo(flaws): seed the seven deliberate regressions` commit).

## Why the scan runs from inside `demo-start`

`security_scan` mixes two rule families:

| family       | rules                                                        | source of truth                    |
|--------------|--------------------------------------------------------------|------------------------------------|
| source-side  | `raw_sql`, `hardcoded_secret`, `absent_tests`                | files under the scanned tree       |
| live process | `missing_auth`, `missing_rate_limit`, `missing_pydantic`, `n_plus_one` | the Django process the command runs in |

Running from the main checkout with `--root ../demo-start/backend` therefore
scores only the source-side family (3/7). These runners `cd` into
`../demo-start/backend` and use its (junctioned) `.venv`, so every rule
measures the flawed app itself: **7/7**.

## Loop

1. Let Bob edit files under `../demo-start` -- working tree only, never committed.
2. Score the attempt:

   ```powershell
   benchmark/run.ps1 bob-attempt-1     # or: benchmark/run.sh bob-attempt-1
   ```

   The scan runs from inside `demo-start` with `--branch <label>`; exit code
   `0` = no critical findings remain, `1` = criticals remain, `2` = misconfig.
   A transcript lands in `backend/logs/<label>.log` (gitignored). Default
   label: `bob-attempt-<unix-seconds>`.
3. Wipe the attempt before the next round:

   ```powershell
   cd ../demo-start
   git restore .
   ```

   Bob's diffs are never committed; the tree returns to the frozen flawed
   baseline exactly. (Repo hint: `git reset` is not needed -- `git restore .`
   discards the working-tree changes.)

Scored runs append to **demo-start's own** scan history (`ScanRun` rows in
its `backend/db.sqlite3`), so `manage.py security_scan` (or a dashboard served
from `demo-start/backend`) shows the 7 -> 0 trend across attempts.

Fresh machine? See "Reproducing the benchmark on a fresh machine" in the
top-level `README.md` -- the only prerequisites are Git and Python 3.13.
