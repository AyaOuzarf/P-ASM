"""
certs_normalizer.py

Lit tous les fichiers scanner/scans/certs_*.json (sortie de scanner/certs.py)
et produit deux vues agregees dans normalizers/certs_normalized.json :

- "by_domain"   : statistiques globales par domaine racine (nombre de
                  sous-domaines, sous-domaines encore actifs, emetteurs,
                  expiration la plus proche)
- "by_subdomain": la meme chose mais par nom exact de sous-domaine (utile
                  pour enrichir chaque actif individuel dans le dashboard,
                  y compris les sous-domaines reveles uniquement par les
                  logs de certificats et absents de Subfinder/Amass)

Format d'entree attendu (produit par scanner/certs.py) :
{
  "domain": "sekera-group.com",
  "total_unique_subdomains": 4,
  "rejected_malformed": [],
  "subdomains": [
    {
      "subdomain": "gitlab.sekera-group.com",
      "domain": "sekera-group.com",
      "issuer": "C=US, O=Let's Encrypt, CN=R12",
      "valid_from": "2026-07-06T14:45:28Z",
      "valid_to": "2026-10-04T14:45:27Z"
    },
    ...
  ]
}
"""
import glob
import json
import os
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANS_DIR = os.path.join(BASE_DIR, "scanner", "scans")
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs_normalized.json")


def parse_date(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    # crt.sh renvoie parfois des dates sans indicateur de fuseau (naive),
    # contrairement a Cert Spotter qui ajoute toujours "Z" (UTC). On force
    # UTC dans ce cas pour pouvoir comparer avec `now`, qui est aware.
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def normalize():
    now = datetime.now(timezone.utc)
    by_domain = {}
    by_subdomain = {}

    for filepath in sorted(glob.glob(os.path.join(SCANS_DIR, "certs_*.json"))):
        filename = os.path.basename(filepath)
        fallback_domain = filename.replace("certs_", "").replace(".json", "")

        with open(filepath, encoding="utf-8") as f:
            data = json.load(f)

        domain = data.get("domain", fallback_domain)
        subdomain_entries = data.get("subdomains", [])
        rejected = data.get("rejected_malformed", [])

        issuers = set()
        expiries = []
        active_count = 0

        for entry in subdomain_entries:
            name = (entry.get("subdomain") or "").strip().lower()
            if not name:
                continue

            issuer = entry.get("issuer")
            valid_to = parse_date(entry.get("valid_to"))
            is_active = valid_to is not None and valid_to > now

            if issuer:
                issuers.add(issuer)
            if is_active:
                active_count += 1
            if valid_to:
                expiries.append(valid_to)

            # Chaque nom n'apparait qu'une fois par fichier (certs.py deduplique
            # deja), mais un meme sous-domaine pourrait en theorie ressortir de
            # plusieurs fichiers/domaines racine -> on fusionne proprement.
            bucket = by_subdomain.setdefault(name, {
                "domain": domain, "count": 0, "issuers": set(),
                "soonest_expiry": None, "active": False,
            })
            bucket["count"] += 1
            if issuer:
                bucket["issuers"].add(issuer)
            if is_active:
                bucket["active"] = True
            if valid_to and (bucket["soonest_expiry"] is None or valid_to < bucket["soonest_expiry"]):
                bucket["soonest_expiry"] = valid_to

        by_domain[domain] = {
            "total_subdomains": len(subdomain_entries),
            "active_subdomains": active_count,
            "rejected_malformed_count": len(rejected),
            "issuers": sorted(issuers),
            "soonest_expiry": min(expiries).isoformat() if expiries else None,
        }

        print(f"[Certs] {domain} -> {len(subdomain_entries)} sous-domaine(s), "
              f"{active_count} actif(s), {len(rejected)} rejete(s)")

    # convertit les sets/datetimes accumules dans by_subdomain en types serialisables
    by_subdomain_serialized = {
        name: {
            "domain": bucket["domain"],
            "count": bucket["count"],
            "issuers": sorted(bucket["issuers"]),
            "active": bucket["active"],
            "soonest_expiry": bucket["soonest_expiry"].isoformat() if bucket["soonest_expiry"] else None,
        }
        for name, bucket in by_subdomain.items()
    }

    result = {"by_domain": by_domain, "by_subdomain": by_subdomain_serialized}

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    print(f"[OK] {len(by_domain)} domaine(s), {len(by_subdomain_serialized)} sous-domaine(s) unique(s) -> {OUTPUT_FILE}")
    return result


if __name__ == "__main__":
    normalize()