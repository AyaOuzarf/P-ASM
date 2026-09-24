"""
dns_enum_normalizer.py

Lit les sorties brutes de scanner/subfinder.py (scanner/scans/subfinder_*.txt)
et scanner/amass.py (scanner/scans/amass_*.txt) - un sous-domaine par ligne -
et produit une vue agregee dans normalizers/dns_enum_normalized.json, avec
la meme convention que certs_normalized.json :

- "by_domain"   : nombre de sous-domaines uniques decouverts par domaine
                  racine, avec repartition par source (subfinder/amass)
- "by_subdomain": pour chaque nom exact decouvert, la liste des outils qui
                  l'ont trouve (utile pour croiser avec certs_normalized.json
                  et reperer les sous-domaines reveles uniquement par les
                  logs de certificats et absents de l'enumeration DNS passive,
                  ou l'inverse)
"""
import glob
import json
import os
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANS_DIR = os.path.join(BASE_DIR, "scanner", "scans")
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dns_enum_normalized.json")

# amass enum -passive (sans -json) produit un texte de relations du type :
#   "nom.domaine.com (FQDN) --> a_record --> 1.2.3.4 (IPAddress)"
#   "domaine.com (FQDN) --> ns_record --> ns1.cloudflare.com (FQDN)"
# On extrait tous les tokens marques "(FQDN)", cote source ET cote cible
# (les CNAME/NS peuvent pointer vers un FQDN externe hors perimetre, filtre
# ensuite par le suffixe du domaine).
FQDN_TOKEN_RE = re.compile(r"([a-zA-Z0-9][a-zA-Z0-9.\-]*)\s*\(FQDN\)")

# (prefixe de fichier, nom de la source, format)
SOURCES = [
    ("subfinder_", "subfinder", "plain"),
    ("amass_", "amass", "amass_graph"),
]


def read_file_content(filepath):
    """Tolerant a l'encodage : la plupart des fichiers sont en UTF-8 (ecrits
    par amass.py/subfinder.py), mais un fichier genere ou re-sauvegarde
    manuellement sous Windows (ex: redirection PowerShell '>') peut se
    retrouver en UTF-16 avec BOM. On essaie plusieurs encodages avant
    d'abandonner."""
    for encoding in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            with open(filepath, encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, UnicodeError):
            continue
    print(f"    [!] Impossible de decoder {filepath}, fichier ignore.")
    return None


def read_hostnames_plain(filepath, domain):
    """Format Subfinder : un nom d'hote par ligne."""
    content = read_file_content(filepath)
    if content is None:
        return set()

    names = set()
    for line in content.splitlines():
        name = line.strip().lower()
        if name and name.endswith(domain):
            names.add(name)
    return names


def read_hostnames_amass_graph(filepath, domain):
    """Format Amass (sortie par defaut, texte de relations) : on extrait
    uniquement les tokens marques "(FQDN)" qui appartiennent au domaine
    cible, en ignorant les IP/ASN/netblocks et les FQDN externes references
    par des relations sortantes (ex: serveurs de noms tiers, CNAME externes)."""
    content = read_file_content(filepath)
    if content is None:
        return set()

    names = set()
    for match in FQDN_TOKEN_RE.finditer(content):
        name = match.group(1).strip().lower().rstrip(".")
        if name.endswith(domain):
            names.add(name)
    return names


READERS = {
    "plain": read_hostnames_plain,
    "amass_graph": read_hostnames_amass_graph,
}


def normalize():
    by_domain = {}
    by_subdomain = {}

    for prefix, source_name, fmt in SOURCES:
        reader = READERS[fmt]
        pattern = os.path.join(SCANS_DIR, f"{prefix}*.txt")
        for filepath in sorted(glob.glob(pattern)):
            filename = os.path.basename(filepath)
            domain = filename.replace(prefix, "").replace(".txt", "")

            names = reader(filepath, domain)

            domain_bucket = by_domain.setdefault(domain, {
                "total_subdomains": 0,
                "by_source_count": {},
            })
            domain_bucket["by_source_count"][source_name] = len(names)

            for name in names:
                sub_bucket = by_subdomain.setdefault(name, {
                    "domain": domain,
                    "sources": set(),
                })
                sub_bucket["sources"].add(source_name)

            print(f"[{source_name}] {domain} -> {len(names)} sous-domaine(s)")

    # total_subdomains par domaine = union des noms trouves par toutes les
    # sources pour ce domaine (pas la somme, pour eviter de compter en double
    # les noms trouves a la fois par subfinder et amass)
    for domain in by_domain:
        by_domain[domain]["total_subdomains"] = sum(
            1 for b in by_subdomain.values() if b["domain"] == domain
        )

    by_subdomain_serialized = {
        name: {
            "domain": bucket["domain"],
            "sources": sorted(bucket["sources"]),
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