# Passive re-run commands

These commands use a detached Git worktree, so the current `scans/` and
`normalizers/` files in the main project are not overwritten.

```powershell
$run = "verification\live-runs\$(Get-Date -Format yyyyMMdd-HHmmss)"
$worktree = Join-Path $run "project"
$python = (Resolve-Path ".\.venv\Scripts\python.exe").Path
New-Item -ItemType Directory -Force $run | Out-Null
git worktree add --detach $worktree HEAD
Push-Location $worktree

& $python scanner\subfinder.py
& $python scanner\amass.py
& $python scanner\assetfinder.py
& $python scanner\certs.py

& $python normalizers\subfinder_normalizer.py
& $python normalizers\amass_normalizer.py
& $python normalizers\assetfinder_normalizer.py
& $python normalizers\certs_normalizer.py
& $python normalizers\dns_enum_normalizer.py
& $python normalizers\takeover_detector.py

& $python -m pytest -q
Pop-Location
```

Optional passive API checks:

```powershell
& .\.venv\Scripts\python.exe scanner\shodan_scanner.py
& .\.venv\Scripts\python.exe normalizers\shodan_normalizer.py
& .\.venv\Scripts\python.exe normalizers\threat_intel_scanner.py
```

Censys has no automated collector in this repository. Its normalizer only
processes manually collected JSON data. Configure API keys only in the current
PowerShell session and never commit them.
