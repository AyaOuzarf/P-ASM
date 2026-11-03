"""
merge_normalizer.py

Fusionne les trois vues normalisees (certs_normalized.json,
subfinder_normalized.json, amass_normalized.json) en une seule vue
unifiee par sous-domaine, prete pour le dashboard.

Pour chaque sous-domaine (union de toutes les sources), on rassemble :
- la liste des outils qui l'ont decouvert ("sources")
- les infos de certificat si disponibles (emetteurs, actif/expire, expiration)
- un flag "cert_only" : decouvert uniquement via les logs de certificats,
  absent de l'enumeration DNS passive (Subfinder/Amass) - signal utile en
  EASM, ca peut reveler un actif oublie ou mal documente

Produit normalizers/merged_normalized.json avec la structure :
{
  "by_domain": {
    "<domaine>": {
      "total_subdomains": int,
      "by_source_count": {"certs": int, "subfinder": int, "amass": int},
      "cert_only_count": int,
      "active_certificates": int,
      "issuers": [...],
      "soonest_expiry": "..." | null
    }
  },
  "by_subdomain": {
    "<nom>": {
      "domain": "...",
      "sources": ["certs", "subfinder", "amass"],   # sous-ensemble present
      "cert_only": bool,
      "certificate": {                               # null si pas de cert connu
        "issuers": [...], "active": bool, "soonest_expiry": "..." | null
      }
    }
  }
}
"""
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CERTS_FILE = os.path.join(BASE_DIR, "certs_normalized.json")
SUBFINDER_FILE = os.path.join(BASE_DIR, "subfinder_normalized.json")
AMASS_FILE = os.path.join(BASE_DIR, "amass_normalized.json")
OUTPUT_FILE = os.path.join(BASE_DIR, "merged_normalized.json")


def load_json(filepath):
    """Load one JSON input file or return an empty structure if absent."""
    if not os.path.exists(filepath):
        print(f"    [!] Fichier introuvable, ignore : {filepath}")
        return {"by_domain": {}, "by_subdomain": {}}
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


def merge():
    """Merge discovery and certificate records into one auxiliary report."""
    certs = load_json(CERTS_FILE)
    subfinder = load_json(SUBFINDER_FILE)
    amass = load_json(AMASS_FILE)

    certs_sub = certs.get("by_subdomain", {})
    subfinder_sub = subfinder.get("by_subdomain", {})
    amass_sub = amass.get("by_subdomain", {})

    # union de tous les noms de sous-domaines connus, toutes sources confondues
    all_names = set(certs_sub) | set(subfinder_sub) | set(amass_sub)

    by_subdomain = {}
    for name in all_names:
        sources = []
        domain = None
        certificate = None

        if name in certs_sub:
            sources.append("certs")
            entry = certs_sub[name]
            domain = entry.get("domain")
            certificate = {
                "issuers": entry.get("issuers", []),
                "active": entry.get("active", False),
                "soonest_expiry": entry.get("soonest_expiry"),
            }

        if name in subfinder_sub:
            sources.append("subfinder")
            domain = domain or subfinder_sub[name].get("domain")

        if name in amass_sub:
            sources.append("amass")
            domain = domain or amass_sub[name].get("domain")

        cert_only = sources == ["certs"]

        by_subdomain[name] = {
            "domain": domain,
            "sources": sorted(sources),
            "cert_only": cert_only,
            "certificate": certificate,
        }

    # agregation par domaine racine
    by_domain = {}
    for name, entry in by_subdomain.items():
        domain = entry["domain"]
        if domain is None:
            continue

        bucket = by_domain.setdefault(domain, {
            "total_subdomains": 0,
            "by_source_count": {"certs": 0, "subfinder": 0, "amass": 0},
            "cert_only_count": 0,
            "active_certificates": 0,
            "issuers": set(),
            "expiries": [],
        })

        bucket["total_subdomains"] += 1
        for source in entry["sources"]:
            bucket["by_source_count"][source] += 1
        if entry["cert_only"]:
            bucket["cert_only_count"] += 1
        if entry["certificate"]:
            if entry["certificate"]["active"]:
                bucket["active_certificates"] += 1
            for issuer in entry["certificate"]["issuers"]:
                bucket["issuers"].add(issuer)
            if entry["certificate"]["soonest_expiry"]:
                bucket["expiries"].append(entry["certificate"]["soonest_expiry"])

    by_domain_serialized = {}
    for domain, bucket in by_domain.items():
        by_domain_serialized[domain] = {
            "total_subdomains": bucket["total_subdomains"],
            "by_source_count": bucket["by_source_count"],
            "cert_only_count": bucket["cert_only_count"],
            "active_certificates": bucket["active_certificates"],
            "issuers": sorted(bucket["issuers"]),
            "soonest_expiry": min(bucket["expiries"]) if bucket["expiries"] else None,
        }

    result = {"by_domain": by_domain_serialized, "by_subdomain": by_subdomain}

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)

    total_cert_only = sum(1 for e in by_subdomain.values() if e["cert_only"])
    print(f"[OK] {len(by_domain_serialized)} domaine(s), {len(by_subdomain)} sous-domaine(s) unique(s) au total")
    print(f"     dont {total_cert_only} decouvert(s) uniquement via les certificats "
          f"(absents de Subfinder/Amass) -> {OUTPUT_FILE}")
    return result


if __name__ == "__main__":
    merge()
