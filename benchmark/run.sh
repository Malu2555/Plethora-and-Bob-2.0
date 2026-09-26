#!/usr/bin/env bash
# benchmark/run.sh -- score one Bob 2.0 attempt against the demo-start worktree.
#
# The scan MUST run from inside demo-start: its Django process is what the
# registry rules (missing_auth / missing_rate_limit / missing_pydantic) and
# the N+1 runtime probe inspect. From the main checkout with --root only the
# source-side rules would fire (3/7).
#
# Usage (from anywhere inside this repo):
#   benchmark/run.sh                  # label: bob-attempt-<unix-ts>
#   benchmark/run.sh bob-attempt-7    # explicit label
#
# Exit code mirrors the scan: 0 = clean, 1 = critical findings remain.
# Transcript: backend/logs/<label>.log (gitignored).
#
# After scoring, wipe Bob's uncommitted session:
#   cd ../demo-start && git restore .

set -euo pipefail

LABEL="${1:-bob-attempt-$(date +%s)}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)"
DEMO_START="$(dirname "$REPO_ROOT")/demo-start"
BACKEND="$DEMO_START/backend"

if [[ ! -f "$BACKEND/manage.py" ]]; then
    echo "fatal: demo-start worktree not found at $DEMO_START" >&2
    echo "       create it with: git worktree add ../demo-start -b demo-start origin/demo-start" >&2
    exit 2
fi

PY="$BACKEND/.venv/bin/python"
[[ -x "$PY" ]] || PY="$BACKEND/.venv/Scripts/python.exe"   # Windows (Git Bash)
if [[ ! -x "$PY" ]]; then
    echo "fatal: no venv under $BACKEND/.venv -- see README.md (fresh machine setup)" >&2
    exit 2
fi

LOG_DIR="$REPO_ROOT/backend/logs"
mkdir -p "$LOG_DIR"
LOG="$LOG_DIR/$LABEL.log"

set +e
( cd "$BACKEND" && "$PY" manage.py security_scan --branch "$LABEL" ) 2>&1 | tee "$LOG"
CODE="${PIPESTATUS[0]}"
set -e

if [[ "$CODE" -eq 0 ]]; then
    echo "[$LABEL] clean -- no critical findings remain. log: $LOG"
else
    echo "[$LABEL] exit_code=$CODE -- criticals remain. log: $LOG"
    echo "[$LABEL] wipe before the next attempt: cd ../demo-start && git restore ."
fi
exit "$CODE"
