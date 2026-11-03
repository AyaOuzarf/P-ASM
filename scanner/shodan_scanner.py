"""
shodan_scanner.py - interroge Shodan par CERTIFICAT (pas par IP resolue via
DNS), pour chaque domaine du perimetre.

Pourquoi pas par IP : les domaines du perimetre sont proteges par Cloudflare
(WAF/CDN), donc resoudre le domaine en IP puis interroger Shodan sur cette IP
ne renvoie que l'infrastructure Cloudflare (edge node generique), jamais le
vrai serveur d'origine.

Cette version cherche a la place les hotes qui presentent un certificat TLS
correspondant au domaine, ou qu'ils soient sur internet. Si un serveur
d'origine mal configure repond encore directement avec ce certificat sans
passer par Cloudflare, cette methode peut le reveler - une decouverte EASM
bien plus utile qu'un simple lookup d'IP.

Utilise l'endpoint "search" de Shodan (consomme des credits de recherche,
distincts et plus limites que les credits de "host lookup" - teste avec
parcimonie).

Necessite: pip install shodan, et une cle API valide (shodan init TA_CLE,
verifie au prealable avec 'shodan info').
"""
import json
import os
import sys
import time
from pathlib import Path

try:
    import shodan as shodan_scanner
except ImportError:
    print("[!] Le package 'shodan' n'est pas installe. Lance: pip install shodan", file=sys.stderr)
    sys.exit(1)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCANS_DIR = os.path.join(os.path.dirname(BASE_DIR), "scans")

DOMAINS = [
    "sekera-group.com",
    "sec-dojo.com",
    "secdojo.com",
    "vincilogic.com",
    "vinci-logic.com",
]

REQUEST_PAUSE = 2  # secondes entre deux recherches, pour rester sous les limites du compte gratuit


def load_api_key() -> str:
    key = os.environ.get("SHODAN_API_KEY")
    if key:
        return key.strip()

    candidates = [
        Path.home() / ".config" / "shodan" / "api_key",
        Path(os.environ.get("USERPROFILE", "")) / ".config" / "shodan" / "api_key",
        Path.home() / ".shodan" / "api_key",
        Path(os.environ.get("USERPROFILE", "")) / ".shodan" / "api_key",
    ]
    for key_file in candidates:
        try:
            if key_file.exists():
                found = key_file.read_text(encoding="utf-8").strip()
                if found:
                    return found
        except OSError:
            continue

    print("[!] Aucune cle API trouvee. Lance 'shodan init TA_CLE' ou definis SHODAN_API_KEY.", file=sys.stderr)
    sys.exit(1)


def search_by_certificate(api: "shodan_scanner.Shodan", domain: str) -> dict:
    """Cherche les hotes indexes par Shodan presentant un certificat TLS
    correspondant a ce domaine (CN ou SAN), independamment du DNS actuel."""
    query = f'ssl.cert.subject.cn:"{domain}"'
    result = {"domain": domain, "query": query, "total": 0, "matches": []}

    try:
        response = api.search(query)
    except shodan_scanner.exception.APIError as exc:
        print(f"    [!] Erreur Shodan pour {domain}: {exc}", file=sys.stderr)
        return result

    result["total"] = response.get("total", 0)
    for match in response.get("matches", []):
        result["matches"].append({
            "ip": match.get("ip_str"),
            "port": match.get("port"),
            "org": match.get("org"),
            "hostnames": match.get("hostnames", []),
            "location": {
                "country": match.get("location", {}).get("country_name"),
                "city": match.get("location", {}).get("city"),
            },
        })
    return result


def run():
    api = shodan_scanner.Shodan(load_api_key())

    for domain in DOMAINS:
        out_file = os.path.join(SCANS_DIR, f"shodan_{domain}.json")
        print(f"[*] Shodan (recherche par certificat) -> {domain}")

        result = search_by_certificate(api, domain)

        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)

        n = len(result["matches"])
        if n == 0:
            print(f"    -> 0 hote trouve (normal si le serveur d'origine est bien masque par Cloudflare)")
        else:
            print(f"    -> {n} hote(s) trouve(s) !! A verifier : possible exposition d'origine hors Cloudflare")
            for m in result["matches"]:
                print(f"       - {m['ip']}:{m['port']} ({m.get('org')}, {m['location'].get('country')})")

        time.sleep(REQUEST_PAUSE)


if __name__ == "__main__":
    run()