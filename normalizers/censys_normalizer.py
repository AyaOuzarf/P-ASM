"""
censys_normalizer.py

Normalise les resultats Censys vers le schema JSON unifie du projet.

Important : l'API de recherche Censys (`cert.names: ...`) n'est PAS disponible
sur le tier gratuit (erreur 403 "This endpoint requires an organization ID
... Free users can only access this endpoint through the Platform UI").
Les resultats doivent donc etre saisis manuellement depuis l'interface web
(platform.censys.io) dans un fichier source, au format simple suivant :

  scans/censys_raw.json
  [
    {"subdomain": "sekera-group.com", "domain": "sekera-group.com",
     "issuer": "Let's Encrypt", "valid_from": "2026-07-06",
     "valid_to": "2026-10-04", "trusted": true},
    ...
  ]

Ce normaliseur lit ce fichier et produit normalizers/censys_normalized.json
dans le schema commun du projet (subdomain, domain, source, discovered_at).
"""
import json
import os
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_FILE = os.path.join(BASE_DIR, "scans", "censys_raw.json")
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "censys_normalized.json")


def normalize():
    if not os.path.exists(RAW_FILE):
        print(f"[!] Fichier introuvable : {RAW_FILE}")
        print("    Cree-le manuellement avec les resultats vus dans l'interface Censys "
              "(voir le format attendu en tete de ce script).")
        return []

    with open(RAW_FILE, encoding="utf-8") as f:
        raw = json.load(f)

    now = datetime.now(timezone.utc).isoformat()
    normalized = []
    for entry in raw:
        sub = entry["subdomain"].strip().lower()
        domain = entry.get("domain", ".".join(sub.split(".")[-2:])).strip().lower()
        normalized.append({
            "subdomain": sub,
            "domain": domain,
            "source": "censys",
            "discovered_at": now,
            # champs additionnels specifiques a Censys, conserves pour reference
            "cert_issuer": entry.get("issuer"),
            "cert_valid_from": entry.get("valid_from"),
            "cert_valid_to": entry.get("valid_to"),
            "cert_trusted": entry.get("trusted"),
        })

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2, ensure_ascii=False)

    print(f"[✓] {len(normalized)} entree(s) Censys normalisee(s) -> {OUTPUT_FILE}")
    return normalized


if __name__ == "__main__":
    normalize()
