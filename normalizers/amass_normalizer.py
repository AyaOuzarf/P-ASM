"""
amass_normalizer.py

Lit les sorties brutes de scanner/amass.py (scans/amass_*.txt) et
produit normalizers/amass_normalized.json au schema commun du projet
(voir censys_normalizer.py) :

  [
    {"subdomain": "gitlab.sekera-group.com", "domain": "sekera-group.com",
     "source": "amass", "discovered_at": "2026-07-30T12:00:00+00:00"},
    ...
  ]

Ce fichier est lu par app.py::load_source() et fusionne avec subfinder/censys
dans merge_by_subdomain(), qui indexe par r["subdomain"] et accumule
r["source"] pour chaque outil ayant trouve ce nom.

Amass (`amass enum -passive`, sans -json) ne produit pas une liste de noms
mais un texte de relations du type :
    "nom.domaine.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)"
    "domaine.com (FQDN) --> ns_record --> ns1.cloudflare.com (FQDN)"
On extrait uniquement les tokens marques "(FQDN)" qui appartiennent au
domaine cible, en ignorant les IP/ASN/netblocks et les FQDN externes
references par des relations sortantes (serveurs de noms tiers, CNAME
externes, etc.).
"""
import glob
import json
import os
import re
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANS_DIR = os.path.join(BASE_DIR, "scans")
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "amass_normalized.json")

FILE_PREFIX = "amass_"
FQDN_TOKEN_RE = re.compile(r"([a-zA-Z0-9][a-zA-Z0-9.\-]*)\s*\(FQDN\)")
HOSTNAME_RE = re.compile(
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+\.?$"
)


def belongs_to_domain(name, domain):
    return name == domain or name.endswith(f".{domain}")


def read_file_content(filepath):
    """Tolerant a l'encodage : la plupart des fichiers sont en UTF-8 (ecrits
    par amass.py), mais un fichier genere/re-sauvegarde manuellement sous
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
    """Extrait les FQDN internes au domaine depuis le texte de relations Amass."""
    content = read_file_content(filepath)
    if content is None:
        return set()

    names = set()
    if "(FQDN)" in content:
        candidates = (match.group(1) for match in FQDN_TOKEN_RE.finditer(content))
    else:
        candidates = content.splitlines()

    for candidate in candidates:
        name = candidate.strip().lower().rstrip(".")
        if HOSTNAME_RE.fullmatch(name) and belongs_to_domain(name, domain):
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
                "source": "amass",
                "discovered_at": now,
            })

        print(f"[amass] {domain} -> {len(names)} sous-domaine(s)")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2, ensure_ascii=False)

    print(f"[OK] {len(normalized)} entree(s) Amass normalisee(s) -> {OUTPUT_FILE}")
    return normalized


if __name__ == "__main__":
    normalize()