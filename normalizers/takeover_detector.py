"""
takeover_detector.py

Detecte les sous-domaines potentiellement vulnerables a une prise de
controle (subdomain takeover / dangling CNAME) : un enregistrement CNAME
qui pointe vers un service tiers (hebergeur SaaS, CDN, PaaS...) qui n'est
plus reclame. Un attaquant peut alors enregistrer la ressource correspondante
chez ce fournisseur et servir du contenu arbitraire depuis le sous-domaine
de la victime (usurpation, phishing, vol de cookies/session, etc.).

Deux signaux, cumulables :
  1. known_vulnerable_service : le CNAME pointe vers un fournisseur connu
     pour ce type de risque (GitHub Pages, Heroku, S3, Azure, etc.) - liste
     inspiree du projet communautaire "can-i-take-over-xyz".
  2. unresolved_target : le nom cible du CNAME ne resout plus du tout (DNS
     NXDOMAIN) - signal fort de ressource abandonnee, quel que soit le
     fournisseur.

Source des donnees : les fichiers scans/amass_*.txt (sortie brute
"amass enum -passive"), qui contiennent deja les relations CNAME sous la
forme :
    "sous.domaine.com (FQDN) --> cname_record --> cible.exemple.com (FQDN)"

Produit normalizers/takeover_findings.json :
[
  {
    "subdomain": "old.sekera-group.com",
    "domain": "sekera-group.com",
    "cname_target": "old-project.herokuapp.com",
    "signals": ["known_vulnerable_service", "unresolved_target"],
    "confidence": "high",
    "service_hint": "Heroku"
  },
  ...
]
"""
import glob
import json
import os
import re
import socket

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANS_DIR = os.path.join(BASE_DIR, "scans")
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "takeover_findings.json")

FILE_PREFIX = "amass_"
DNS_TIMEOUT = 4  # secondes par resolution DNS

# Relation CNAME dans la sortie graphe d'Amass :
#   "source (FQDN) --> cname_record --> cible (FQDN)"
CNAME_RE = re.compile(
    r"([a-zA-Z0-9][a-zA-Z0-9.\-]*)\s*\(FQDN\)\s*-->\s*cname_record\s*-->\s*"
    r"([a-zA-Z0-9][a-zA-Z0-9.\-]*)\s*\(FQDN\)"
)


def belongs_to_domain(name, domain):
    return name == domain or name.endswith(f".{domain}")


# Fournisseurs connus pour heberger des ressources "reclamables" par un
# attaquant si le sous-domaine client n'est plus utilise. Liste non
# exhaustive, inspiree de can-i-take-over-xyz. Cle = suffixe de domaine,
# valeur = nom lisible du service pour le rapport.
VULNERABLE_SERVICES = {
    "github.io": "GitHub Pages",
    "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku",
    "s3.amazonaws.com": "AWS S3",
    "s3-website": "AWS S3 (site statique)",
    "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure",
    "blob.core.windows.net": "Azure Blob Storage",
    "trafficmanager.net": "Azure Traffic Manager",
    "bitbucket.io": "Bitbucket Pages",
    "surge.sh": "Surge.sh",
    "pantheonsite.io": "Pantheon",
    "wordpress.com": "WordPress.com",
    "wpengine.com": "WP Engine",
    "shopify.com": "Shopify",
    "myshopify.com": "Shopify",
    "zendesk.com": "Zendesk",
    "statuspage.io": "Statuspage",
    "unbouncepages.com": "Unbounce",
    "tumblr.com": "Tumblr",
    "cargocollective.com": "Cargo Collective",
    "fastly.net": "Fastly",
    "netlify.app": "Netlify",
    "vercel.app": "Vercel",
    "readme.io": "ReadMe",
    "helpscoutdocs.com": "Help Scout",
    "webflow.io": "Webflow",
    "launchrock.com": "LaunchRock",
    "ghost.io": "Ghost",
}


def read_file_content(filepath):
    """Tolerant a l'encodage, meme raison que les autres normalizers du
    projet : certains fichiers Amass peuvent avoir ete resauvegardes en
    UTF-16 (redirection PowerShell) plutot qu'en UTF-8."""
    for encoding in ("utf-8-sig", "utf-16", "cp1252"):
        try:
            with open(filepath, encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, UnicodeError):
            continue
    print(f"    [!] Impossible de decoder {filepath}, fichier ignore.")
    return None


def extract_cname_pairs(filepath, domain):
    """Retourne [(sous_domaine, cible_cname), ...] pour toutes les relations
    CNAME dont la source appartient au domaine cible."""
    content = read_file_content(filepath)
    if content is None:
        return []

    pairs = []
    for match in CNAME_RE.finditer(content):
        source = match.group(1).strip().lower().rstrip(".")
        target = match.group(2).strip().lower().rstrip(".")
        if belongs_to_domain(source, domain):
            pairs.append((source, target))
    return pairs


def match_known_service(target):
    """Retourne le nom lisible du service si la cible correspond a un
    fournisseur connu pour ce risque, sinon None."""
    for suffix, service_name in VULNERABLE_SERVICES.items():
        if suffix in target:
            return service_name
    return None


def target_resolves(target):
    """True si le nom cible resout encore en DNS, False si NXDOMAIN/erreur
    de resolution (signal de ressource abandonnee), None si on n'a pas pu
    trancher (timeout reseau, pas de connectivite)."""
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(DNS_TIMEOUT)
    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False
    except socket.timeout:
        return None
    finally:
        socket.setdefaulttimeout(original_timeout)


def analyze():
    findings = []

    pattern = os.path.join(SCANS_DIR, f"{FILE_PREFIX}*.txt")
    for filepath in sorted(glob.glob(pattern)):
        filename = os.path.basename(filepath)
        domain = filename.replace(FILE_PREFIX, "").replace(".txt", "")

        pairs = extract_cname_pairs(filepath, domain)
        print(f"[takeover] {domain} -> {len(pairs)} relation(s) CNAME a analyser")

        for subdomain, target in pairs:
            signals = []
            service_hint = match_known_service(target)
            if service_hint:
                signals.append("known_vulnerable_service")

            resolves = target_resolves(target)
            if resolves is False:
                signals.append("unresolved_target")

            if not signals:
                continue

            confidence = "high" if len(signals) == 2 else "medium"

            findings.append({
                "subdomain": subdomain,
                "domain": domain,
                "cname_target": target,
                "signals": signals,
                "confidence": confidence,
                "service_hint": service_hint,
            })
            print(f"    [!] {subdomain} -> CNAME {target} "
                  f"(signaux: {', '.join(signals)}, confiance: {confidence})")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)

    print(f"[OK] {len(findings)} sous-domaine(s) potentiellement vulnerable(s) "
          f"a un takeover -> {OUTPUT_FILE}")
    return findings


if __name__ == "__main__":
    analyze()