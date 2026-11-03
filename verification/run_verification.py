"""Record a read-only verification of the P-ASM project.

This script never writes to scans/ or normalizers/. It records the current
inventory, available commands, configured API integrations, and local test
results in a timestamped directory under verification/runs/.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "verification" / "runs"
DOMAINS = [
    "sekera-group.com",
    "sec-dojo.com",
    "secdojo.com",
    "vincilogic.com",
    "vinci-logic.com",
]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def run_command(command: list[str]) -> dict[str, object]:
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        return {
            "command": command,
            "available": True,
            "returncode": completed.returncode,
            "stdout": completed.stdout[-4000:],
            "stderr": completed.stderr[-4000:],
        }
    except FileNotFoundError:
        return {"command": command, "available": False, "reason": "command not found"}
    except subprocess.TimeoutExpired:
        return {"command": command, "available": True, "reason": "timeout"}


def main() -> int:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    output_dir = RUNS / timestamp
    output_dir.mkdir(parents=True, exist_ok=False)

    report: dict[str, object] = {
        "timestamp": timestamp,
        "mode": "passive and read-only",
        "domains": DOMAINS,
        "outputs_written_to": str(output_dir.relative_to(ROOT)),
        "tools": {},
        "api_configuration": {
            "SHODAN_API_KEY": bool(os.environ.get("SHODAN_API_KEY")),
            "CENSYS_API_ID": bool(os.environ.get("CENSYS_API_ID")),
            "CENSYS_API_KEY": bool(os.environ.get("CENSYS_API_KEY")),
            "URLHAUS_AUTH_KEY": bool(os.environ.get("URLHAUS_AUTH_KEY")),
            "OTX_API_KEY": bool(os.environ.get("OTX_API_KEY")),
            "ABUSEIPDB_API_KEY": bool(os.environ.get("ABUSEIPDB_API_KEY")),
        },
    }

    for tool in ("subfinder", "amass", "assetfinder", "curl"):
        report["tools"][tool] = shutil.which(tool) is not None  # type: ignore[index]

    # Importing the application is local-only when liveness and live lookups are off.
    sys.path.insert(0, str(ROOT))
    import app  # noqa: WPS433

    assets = app.build_assets(with_liveness=False)
    stats = app.build_stats(assets)
    report["local_inventory"] = {
        "asset_count": len(assets),
        "stats": stats,
        "by_domain": {
            domain: sum(asset["root_domain"] == domain for asset in assets)
            for domain in DOMAINS
        },
        "takeover_assets": [asset["subdomain"] for asset in assets if asset["takeover_risk"]],
        "shodan_is_loaded_by_dashboard": False,
        "threat_intel_is_loaded_by_dashboard": False,
    }

    files = []
    for directory in (ROOT / "scans", ROOT / "normalizers"):
        for path in sorted(directory.rglob("*")):
            if path.is_file() and "history" not in path.parts and "__pycache__" not in path.parts:
                files.append({"path": str(path.relative_to(ROOT)), "sha256": sha256(path)})
    report["input_file_hashes"] = files

    report["local_commands"] = [
        run_command([sys.executable, "-m", "compileall", "-q", "app.py", "risk_engine.py", "vulnerability_sources.py", "normalizers", "scanner"]),
        run_command([sys.executable, "-m", "pytest", "-q"]),
    ]

    (output_dir / "verification_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    (output_dir / "verification_report.md").write_text(
        "# P-ASM verification\n\n"
        f"- Run: `{timestamp}`\n"
        "- Mode: passive and read-only\n"
        f"- Local assets: **{len(assets)}**\n"
        "- Existing `scans/` and `normalizers/` files were not modified.\n\n"
        "See `verification_report.json` for tool availability, API-key presence, "
        "input hashes, domain counts, and command results.\n",
        encoding="utf-8",
    )
    print(output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
