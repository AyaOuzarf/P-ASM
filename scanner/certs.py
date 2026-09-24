"""
certs_scanner.py - interroge crt.sh (logs de transparence de certificats)
pour chaque domaine du perimetre. Gratuit, illimite, aucune cle API requise.

Contrairement a Shodan/Censys, crt.sh est directement interrogeable en HTTP
sans authentification. Il republie les certificats emis publiquement
(Let's Encrypt, Sectigo, etc.), ce qui revele les noms de domaine couverts,
les dates de validite, et l'autorite de certification - la meme information
que celle relevee manuellement sur Censys plus tot dans ce projet, mais
automatisee et sans limite de credits.
"""
import json
import os
import re
import sys
import time
import urllib.request
import urllib.error

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCANS_DIR = os.path.join(BASE_DIR, "scans")

DOMAINS = [
    "sekera-group.com",
    "sec-dojo.com",
    "secdojo.com",
    "vincilogic.com",
    "vinci-logic.com",
]

# Un nom d'hote valide : labels alphanumeriques/tirets separes par des points.
# Rejette tout ce qui contient des caracteres hors de ce jeu (ex: formatage
# Markdown "[nom](url)" observe dans certaines reponses Cert Spotter/crt.sh
# malformees, ou toute autre anomalie de donnee brute).
VALID_HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,62}[a-z0-9])?)+$")


def is_valid_hostname(name: str) -> bool:
    return bool(VALID_HOSTNAME_RE.match(name)) and len(name) <= 253

REQUEST_PAUSE = 2       # secondes entre deux requetes, pour rester correct envers crt.sh
TIMEOUT = 40             # crt.sh est notoirement lent/instable, timeout genereux
RETRIES = 4


def query_crtsh(domain: str) -> list:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    last_error = None

    for attempt in range(1, RETRIES + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "easm-dashboard/1.0"})
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                raw = resp.read().decode("utf-8", errors="ignore")
                return json.loads(raw)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt < RETRIES:
                wait = 5 * attempt  # backoff progressif : 5s, 10s, 15s...
                print(f"    [i] crt.sh indisponible (tentative {attempt}/{RETRIES}), "
                      f"nouvelle tentative dans {wait}s...", file=sys.stderr)
                time.sleep(wait)

    print(f"    [!] crt.sh definitivement indisponible pour {domain} apres {RETRIES} tentatives "
          f"({last_error}).", file=sys.stderr)
    return []


def query_all_sources(domain: str) -> list:
    """Interroge crt.sh ET Cert Spotter systematiquement (pas seulement en
    secours) et fusionne les deux jeux de resultats bruts.

    Les deux services indexent les logs de transparence de certificats de
    facon independante et n'ont pas forcement la meme couverture au meme
    instant (crt.sh peut manquer une emission recente que Cert Spotter a
    deja indexee, ou inversement). Combiner les deux donne une image plus
    complete et plus stable que de ne se reposer que sur l'un des deux -
    summarize() deduplique de toute facon en aval, donc les doublons entre
    sources ne posent pas de probleme."""
    crtsh_entries = query_crtsh(domain)
    print(f"    [i] crt.sh: {len(crtsh_entries)} entree(s)", file=sys.stderr)

    certspotter_entries = query_certspotter(domain)
    print(f"    [i] Cert Spotter: {len(certspotter_entries)} entree(s)", file=sys.stderr)

    return crtsh_entries + certspotter_entries


def query_certspotter(domain: str) -> list:
    """Source de secours si crt.sh est indisponible : SSLMate Cert Spotter,
    meme principe (logs de transparence de certificats), gratuit sans cle
    API pour un usage leger. Format de reponse different de crt.sh, adapte
    au meme schema {name_value, issuer_name, not_before, not_after} pour que
    summarize() fonctionne sans changement."""
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names&expand=issuer"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "easm-dashboard/1.0"})
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            data = json.loads(raw)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"    [!] Cert Spotter aussi indisponible pour {domain}: {exc}", file=sys.stderr)
        return []

    adapted = []
    for entry in data:
        names = entry.get("dns_names", [])
        issuer = entry.get("issuer", {}).get("name", "") if isinstance(entry.get("issuer"), dict) else ""
        adapted.append({
            "name_value": "\n".join(names),
            "issuer_name": issuer,
            "not_before": entry.get("not_before", ""),
            "not_after": entry.get("not_after", ""),
        })
    return adapted


def summarize(domain: str, raw_entries: list) -> dict:
    """Deduplique par nom de sous-domaine et conserve les dates/emetteur les
    plus recents rencontres pour chacun."""
    by_subdomain = {}
    rejected = []

    for entry in raw_entries:
        names = entry.get("name_value", "").split("\n")
        issuer = entry.get("issuer_name", "")
        not_before = entry.get("not_before", "")
        not_after = entry.get("not_after", "")

        for name in names:
            name = name.strip().lower()
            if not name or "*" in name or not name.endswith(domain):
                continue
            if not is_valid_hostname(name):
                rejected.append(name)
                continue
            existing = by_subdomain.get(name)
            if existing is None or not_before > existing["valid_from"]:
                by_subdomain[name] = {
                    "subdomain": name,
                    "domain": domain,
                    "issuer": issuer,
                    "valid_from": not_before,
                    "valid_to": not_after,
                }

    if rejected:
        print(f"    [!] {len(rejected)} entree(s) rejetee(s) (format invalide) : {rejected}", file=sys.stderr)

    return {
        "domain": domain,
        "total_unique_subdomains": len(by_subdomain),
        "rejected_malformed": rejected,
        "subdomains": sorted(by_subdomain.values(), key=lambda r: r["subdomain"]),
    }


def run():
    os.makedirs(SCANS_DIR, exist_ok=True)

    for domain in DOMAINS:
        out_file = os.path.join(SCANS_DIR, f"certs_{domain}.json")
        print(f"[*] crt.sh + Cert Spotter -> {domain}")

        raw = query_all_sources(domain)
        print(f"    [debug] {len(raw)} entree(s) brute(s) au total (avant fusion) pour {domain}", file=sys.stderr)

        result = summarize(domain, raw)

        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        print(f"    -> {result['total_unique_subdomains']} sous-domaine(s) unique(s) -> {out_file}")
        time.sleep(REQUEST_PAUSE)


if __name__ == "__main__":
    run()