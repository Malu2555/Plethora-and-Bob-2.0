# benchmark/run.ps1 -- score one Bob 2.0 attempt against the demo-start worktree.
#
# The scan MUST run from inside demo-start: its Django process is what the
# registry rules (missing_auth / missing_rate_limit / missing_pydantic) and
# the N+1 runtime probe inspect. From the main checkout with --root only the
# source-side rules would fire (3/7).
#
# Usage (from anywhere inside this repo):
#   pwsh benchmark/run.ps1                  # label: bob-attempt-<unix-ts>
#   pwsh benchmark/run.ps1 bob-attempt-7    # explicit label
#
# Exit code mirrors the scan: 0 = clean, 1 = critical findings remain.
# Transcript: backend/logs/<label>.log (gitignored).
#
# After scoring, wipe Bob's uncommitted session:
#   cd ../demo-start; git restore .

param([string]$Label = ("bob-attempt-" + [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()))

$repoRoot = (git -C $PSScriptRoot rev-parse --show-toplevel).Trim()
$demoStart = Join-Path (Split-Path $repoRoot -Parent) "demo-start"
$backend = Join-Path $demoStart "backend"

if (-not (Test-Path (Join-Path $backend "manage.py"))) {
    Write-Error "demo-start worktree not found at $demoStart -- create it with: git worktree add ../demo-start -b demo-start origin/demo-start"
    exit 2
}

$py = Join-Path $backend ".venv\Scripts\python.exe"
if (-not (Test-Path $py)) { $py = Join-Path $backend ".venv/bin/python" }  # macOS / Linux
if (-not (Test-Path $py)) {
    Write-Error "no venv under $backend\.venv -- see README.md (fresh machine setup)"
    exit 2
}

$logDir = Join-Path $repoRoot "backend\logs"
New-Item -ItemType Directory -Path $logDir -Force | Out-Null
$log = Join-Path $logDir ($Label + ".log")

Push-Location $backend
try {
    & $py manage.py security_scan --branch $Label 2>&1 | Tee-Object -FilePath $log
    $code = $LASTEXITCODE
}
finally {
    Pop-Location
}

if ($code -eq 0) {
    Write-Host "[$Label] clean -- no critical findings remain. log: $log"
} else {
    Write-Host "[$Label] exit_code=$code -- criticals remain. log: $log"
    Write-Host "[$Label] wipe before the next attempt: cd ../demo-start; git restore ."
}
exit $code
