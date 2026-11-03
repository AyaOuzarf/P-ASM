"""
subfinder_normalizer.py

Lit les sorties brutes de scanner/subfinder.py (scans/subfinder_*.txt)
- un sous-domaine par ligne - et produit normalizers/subfinder_normalized.json
au schema commun du projet (voir censys_normalizer.py) :

  [
    {"subdomain": "gitlab.sekera-group.com", "domain": "sekera-group.com",
     "source": "subfinder", "discovered_at": "2026-07-30T12:00:00+00:00"},
    ...
  ]

Ce fichier est lu par app.py::load_source() et fusionne avec amass/censys
dans merge_by_subdomain(), qui indexe par r["subdomain"] et accumule
r["source"] pour chaque outil ayant trouve ce nom.
"""
import glob
import json
import os
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANS_DIR = os.path.join(BASE_DIR, "scans")
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "subfinder_normalized.json")

FILE_PREFIX = "subfinder_"


def belongs_to_domain(name, domain):
    return name == domain or name.endswith(f".{domain}")


def read_file_content(filepath):
    """Tolerant a l'encodage : la plupart des fichiers sont en UTF-8 (ecrits
    par subfinder.py), mais un fichier genere/re-sauvegarde manuellement sous
    Windows (ex: redirection PowerShell '>') peut se retrouver en UTF-16 avec
    BOM. On essaie plusieurs encodages avant d'abandonner."""
    for encoding in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            with open(filepath, encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, UnicodeError):
            continue
    print(f"    [!] Impossible de decoder {filepath}, fichier ignore.")
    return None


def read_hostnames(filepath, domain):
    """Format Subfinder : un nom d'hote par ligne."""
    content = read_file_content(filepath)
    if content is None:
        return set()

    names = set()
    for line in content.splitlines():
        name = line.strip().lower()
        if belongs_to_domain(name, domain):
            names.add(name)
    return names


def normalize():
    now = datetime.now(timezone.utc).isoformat()
    normalized = []

    pattern = os.path.join(SCANS_DIR, f"{FILE_PREFIX}*.txt")
    for filepath in sorted(glob.glob(pattern)):
        filename = os.path.basename(filepath)
        domain = filename.replace(FILE_PREFIX, "").replace(".txt", "")

        names = read_hostnames(filepath, domain)
        for name in names:
            normalized.append({
                "subdomain": name,
                "domain": domain,
                "source": "subfinder",
                "discovered_at": now,
            })

        print(f"[subfinder] {domain} -> {len(names)} sous-domaine(s)")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2, ensure_ascii=False)

    print(f"[OK] {len(normalized)} entree(s) Subfinder normalisee(s) -> {OUTPUT_FILE}")
    return normalized


if __name__ == "__main__":
    normalize()