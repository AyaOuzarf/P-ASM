"""
threat_intel_scanner.py

Scanner de Threat Intelligence pour l'EASM.

Sources :
- URLhaus
- AlienVault OTX
- AbuseIPDB

Le scanner ne considere jamais l'absence de resultat comme une preuve
qu'un actif est sain. Un finding signifie uniquement qu'un signal a ete
trouve par une des sources interrogees.

Coupe-circuit OTX : si OTX_CIRCUIT_BREAKER_THRESHOLD echecs consecutifs
surviennent (timeout ou erreur reseau), OTX est desactive pour le reste du
scan. Sans ca, un blocage reseau/firewall sur OTX (frequent : certains
reseaux d'entreprise ou FAI bloquent silencieusement les domaines de threat
intelligence) coute un timeout complet par sous-domaine restant - avec
--max-time 15s et 54 sous-domaines, un blocage total peut faire perdre plus
de 13 minutes pour un resultat qui aurait de toute facon ete vide partout.
URLhaus et AbuseIPDB continuent normalement meme si OTX est desactive.
"""

import json
import os
import shutil
import socket
import ssl
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request


# ============================================================
# CONFIGURATION
# ============================================================

try:
    import certifi

    SSL_CONTEXT = ssl.create_default_context(
        cafile=certifi.where()
    )

except ImportError:
    print(
        "[!] Le paquet 'certifi' n'est pas installé. "
        "Lance : pip install certifi"
    )
    SSL_CONTEXT = ssl.create_default_context()


BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

NORMALIZERS_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

OUTPUT_FILE = os.path.join(
    NORMALIZERS_DIR,
    "threat_intel_findings.json"
)


# ============================================================
# URLS API
# ============================================================

URLHAUS_HOST_ENDPOINT = (
    "https://urlhaus-api.abuse.ch/v1/host/"
)

OTX_DOMAIN_ENDPOINT = (
    "https://otx.alienvault.com/"
    "api/v1/indicators/domain/{domain}/general"
)

ABUSEIPDB_ENDPOINT = (
    "https://api.abuseipdb.com/api/v2/check"
)


# ============================================================
# API KEYS
# ============================================================

URLHAUS_AUTH_KEY = os.environ.get(
    "URLHAUS_AUTH_KEY",
    ""
).strip()

OTX_API_KEY = os.environ.get(
    "OTX_API_KEY",
    ""
).strip()

ABUSEIPDB_API_KEY = os.environ.get(
    "ABUSEIPDB_API_KEY",
    ""
).strip()


# ============================================================
# PARAMETRES
# ============================================================

REQUEST_PAUSE = 0.2

TIMEOUT = 20

DNS_TIMEOUT = 4

# OTX est traité séparément avec curl
OTX_CONNECT_TIMEOUT = 10
OTX_TIMEOUT = 30

ABUSEIPDB_MIN_SCORE = 25

OTX_RETRIES = 2

# Coupe-circuit : au-dela de ce nombre d'echecs OTX CONSECUTIFS (timeout ou
# erreur reseau - pas les 404, qui sont une reponse normale "domaine inconnu
# d'OTX"), on arrete d'interroger OTX pour le reste du scan. Reinitialise a
# chaque succes.
OTX_CIRCUIT_BREAKER_THRESHOLD = 3
_otx_consecutive_failures = 0
_otx_disabled = False


# ============================================================
# CURL
# ============================================================

CURL_BIN = (
    shutil.which("curl.exe")
    or shutil.which("curl")
)


# ============================================================
# CHARGEMENT DES SOUS-DOMAINES
# ============================================================

def load_all_subdomains():
    """Load the current E-ASM asset list without performing active probing."""
    """
    Récupère les sous-domaines depuis le pipeline EASM existant.
    """

    import sys

    sys.path.insert(0, BASE_DIR)

    from app import build_assets

    assets = build_assets(
        with_liveness=False
    )

    return [
        (
            a["subdomain"],
            a["root_domain"]
        )
        for a in assets
    ]


# ============================================================
# DNS
# ============================================================

def resolve_ip(hostname):
    """Resolve one hostname to IPv4 for optional reputation lookup."""
    """
    Retourne l'IPv4 résolue du hostname.
    """

    original_timeout = socket.getdefaulttimeout()

    socket.setdefaulttimeout(
        DNS_TIMEOUT
    )

    try:
        return socket.gethostbyname(
            hostname
        )

    except (
        socket.gaierror,
        socket.timeout
    ):
        return None

    finally:
        socket.setdefaulttimeout(
            original_timeout
        )


# ============================================================
# URLHAUS
# ============================================================

def query_urlhaus(host):
    """Query URLhaus for passive malicious-URL intelligence about a host."""
    """
    Interroge URLhaus.
    """

    if not URLHAUS_AUTH_KEY:
        return None

    data = urllib.parse.urlencode(
        {
            "host": host
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        URLHAUS_HOST_ENDPOINT,
        data=data,
        headers={
            "Auth-Key": URLHAUS_AUTH_KEY,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        },
        method="POST",
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=TIMEOUT,
            context=SSL_CONTEXT
        ) as resp:

            result = json.loads(
                resp.read().decode("utf-8")
            )

    except urllib.error.HTTPError as exc:

        if exc.code == 401:
            print(
                f"    [!] URLhaus : clé API invalide "
                f"ou refusée pour {host}."
            )

        else:
            print(
                f"    [!] URLhaus HTTP {exc.code} "
                f"pour {host}"
            )

        return None

    except (
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError
    ) as exc:

        print(
            f"    [!] Erreur URLhaus pour {host} : {exc}"
        )

        return None

    if result.get("query_status") != "ok":
        return None

    urls = result.get(
        "urls",
        []
    )

    threat_types = sorted(
        {
            u.get(
                "threat",
                "unknown"
            )
            for u in urls
            if u.get("threat")
        }
    )

    return {
        "url_count": len(urls),
        "threat_types": threat_types,
        "reference": (
            f"https://urlhaus.abuse.ch/"
            f"host/{host}/"
        ),
    }


# ============================================================
# OTX AVEC CURL (+ coupe-circuit)
# ============================================================

def query_otx(domain):
    """Query AlienVault OTX with a network-failure circuit breaker."""
    """
    Interroge AlienVault OTX pour un domaine.

    Sous Windows, curl.exe est utilisé en priorité.
    Un timeout ou une erreur réseau sur OTX ne bloque jamais
    le reste du scan.

    Coupe-circuit : si OTX_CIRCUIT_BREAKER_THRESHOLD echecs consecutifs
    (timeout/erreur reseau) surviennent, OTX est desactive pour le reste
    du scan - evite de perdre un --max-time complet par sous-domaine
    restant quand le probleme est deja identifie (firewall, blocage
    reseau, rate-limit qui droppe la connexion au lieu de repondre).
    """
    global _otx_consecutive_failures, _otx_disabled

    if not OTX_API_KEY:
        return None

    if _otx_disabled:
        return None

    url = OTX_DOMAIN_ENDPOINT.format(
        domain=urllib.parse.quote(domain, safe="")
    )

    def _record_failure(reason):
        global _otx_consecutive_failures, _otx_disabled
        _otx_consecutive_failures += 1
        if _otx_consecutive_failures >= OTX_CIRCUIT_BREAKER_THRESHOLD and not _otx_disabled:
            _otx_disabled = True
            print(
                f"    [!!] OTX desactive pour le reste du scan : "
                f"{_otx_consecutive_failures} echecs consecutifs "
                f"({reason}). Verifie manuellement la connectivite avec :\n"
                f"         curl -v --connect-timeout 5 --max-time 15 "
                f"-H \"X-OTX-API-KEY: TA_CLE\" "
                f"\"https://otx.alienvault.com/api/v1/indicators/domain/example.com/general\""
            )

    def _record_success():
        global _otx_consecutive_failures
        _otx_consecutive_failures = 0

    # ============================================================
    # CURL - méthode principale sous Windows
    # ============================================================

    if CURL_BIN:

        command = [
            CURL_BIN,
            "--silent",
            "--show-error",
            "--location",

            "--connect-timeout",
            "5",

            "--max-time",
            "15",

            "--header",
            f"X-OTX-API-KEY: {OTX_API_KEY}",

            "--header",
            "Accept: application/json",

            "--header",
            "User-Agent: EASM-Security-Scanner/1.0",

            "--write-out",
            "\n%{http_code}",

            url,
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=20
            )

        except subprocess.TimeoutExpired:
            print(
                f"    [!] OTX timeout pour {domain}"
            )
            _record_failure("timeout subprocess")
            return None

        except Exception as exc:
            print(
                f"    [!] Erreur curl OTX pour {domain} : "
                f"{type(exc).__name__}: {exc}"
            )
            _record_failure(f"{type(exc).__name__}")
            return None

        # --------------------------------------------------------
        # Erreur CURL
        # --------------------------------------------------------

        if result.returncode != 0:

            error = (
                result.stderr.strip()
                or "erreur curl inconnue"
            )

            print(
                f"    [!] OTX curl pour {domain} : {error}"
            )

            # returncode 28 = timeout curl (CURLE_OPERATION_TIMEDOUT) :
            # c'est le cas qui doit alimenter le coupe-circuit. Les autres
            # erreurs curl (ex: DNS local, certificat) comptent aussi comme
            # echec reseau au sens large.
            _record_failure(f"curl exit {result.returncode}")
            return None

        output = result.stdout.strip()

        if not output:
            print(
                f"    [!] OTX réponse vide pour {domain}"
            )
            _record_failure("reponse vide")
            return None

        # --------------------------------------------------------
        # Séparer le JSON du code HTTP
        # --------------------------------------------------------

        lines = output.splitlines()

        if len(lines) < 2:
            print(
                f"    [!] Réponse OTX inattendue pour {domain}"
            )
            _record_failure("reponse inattendue")
            return None

        status_code_raw = lines[-1].strip()
        body = "\n".join(lines[:-1]).strip()

        try:
            status_code = int(status_code_raw)
        except ValueError:
            print(
                f"    [!] Code HTTP OTX invalide pour {domain} : "
                f"{status_code_raw}"
            )
            _record_failure("code HTTP invalide")
            return None

        # --------------------------------------------------------
        # HTTP 401
        # --------------------------------------------------------

        if status_code == 401:
            print(
                f"    [!] OTX : clé API invalide ou refusée "
                f"pour {domain}"
            )
            # Une cle invalide n'est pas un probleme reseau : pas la peine
            # de desactiver OTX pour ca, chaque appel echouera pareil mais
            # ce n'est pas ce que le coupe-circuit cible. On retourne
            # simplement sans alimenter le compteur d'echecs reseau.
            return None

        # --------------------------------------------------------
        # HTTP 404
        # --------------------------------------------------------

        if status_code == 404:
            _record_success()  # 404 = reponse recue normalement, juste "inconnu"
            return None

        # --------------------------------------------------------
        # Autre erreur HTTP
        # --------------------------------------------------------

        if status_code != 200:
            print(
                f"    [!] OTX HTTP {status_code} pour {domain}"
            )
            return None

        # --------------------------------------------------------
        # Parser JSON
        # --------------------------------------------------------

        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            print(
                f"    [!] JSON OTX invalide pour {domain} : {exc}"
            )
            return None

        # Reponse HTTP 200 recue et parsee : le lien reseau fonctionne.
        _record_success()

        # --------------------------------------------------------
        # Lire pulse_info
        # --------------------------------------------------------

        pulse_info = data.get("pulse_info") or {}

        pulse_count = pulse_info.get("count", 0)

        try:
            pulse_count = int(pulse_count)
        except (TypeError, ValueError):
            pulse_count = 0

        # Aucun signal OTX
        if pulse_count <= 0:
            return None

        # Signal trouvé
        print(
            f"    [!] OTX : {domain} -> "
            f"{pulse_count} pulse(s)"
        )

        return {
            "pulse_count": pulse_count,
            "reference": (
                "https://otx.alienvault.com/"
                f"indicator/domain/{domain}"
            ),
        }

    # ============================================================
    # FALLBACK URLLIB
    # ============================================================

    req = urllib.request.Request(
        url,
        headers={
            "X-OTX-API-KEY": OTX_API_KEY,
            "Accept": "application/json",
            "User-Agent": "EASM-Security-Scanner/1.0",
            "Connection": "close",
        },
        method="GET",
    )

    try:

        with urllib.request.urlopen(
            req,
            timeout=15,
            context=SSL_CONTEXT
        ) as resp:

            raw = resp.read().decode("utf-8")
            result = json.loads(raw)

    except urllib.error.HTTPError as exc:

        if exc.code == 401:
            print(
                f"    [!] OTX : clé API invalide ou refusée "
                f"pour {domain}"
            )

        elif exc.code != 404:
            print(
                f"    [!] OTX HTTP {exc.code} pour {domain}"
            )
            _record_failure(f"HTTP {exc.code}")

        return None

    except (
        TimeoutError,
        socket.timeout
    ):
        print(
            f"    [!] OTX timeout pour {domain}"
        )
        _record_failure("timeout urllib")
        return None

    except urllib.error.URLError as exc:
        print(
            f"    [!] Erreur réseau OTX pour "
            f"{domain} : {exc}"
        )
        _record_failure(f"URLError: {exc}")
        return None

    except json.JSONDecodeError:
        print(
            f"    [!] Réponse OTX invalide pour {domain}"
        )
        return None

    except Exception as exc:
        print(
            f"    [!] Exception OTX pour {domain} : "
            f"{type(exc).__name__}: {exc}"
        )
        _record_failure(f"{type(exc).__name__}")
        return None

    _record_success()

    pulse_count = (
        result.get("pulse_info") or {}
    ).get("count", 0)

    try:
        pulse_count = int(pulse_count)
    except (TypeError, ValueError):
        pulse_count = 0

    if pulse_count <= 0:
        return None

    print(
        f"    [!] OTX : {domain} -> "
        f"{pulse_count} pulse(s)"
    )

    return {
        "pulse_count": pulse_count,
        "reference": (
            "https://otx.alienvault.com/"
            f"indicator/domain/{domain}"
        ),
    }

def query_abuseipdb(ip):
    """Query AbuseIPDB and return only findings above the configured threshold."""
    """
    Interroge AbuseIPDB pour une IP.

    Retourne un finding uniquement si le score de confiance
    dépasse ABUSEIPDB_MIN_SCORE.
    """

    if not ABUSEIPDB_API_KEY:
        return None

    params = urllib.parse.urlencode({
        "ipAddress": ip,
        "maxAgeInDays": 90,
    })

    url = f"{ABUSEIPDB_ENDPOINT}?{params}"

    req = urllib.request.Request(
        url,
        headers={
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json",
            "User-Agent": "EASM-Security-Scanner/1.0",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(
            req,
            timeout=TIMEOUT,
            context=SSL_CONTEXT
        ) as resp:

            raw = resp.read().decode("utf-8")
            result = json.loads(raw)

    except urllib.error.HTTPError as exc:

        if exc.code == 401:
            print(
                f"    [!] AbuseIPDB : clé API invalide "
                f"ou refusée pour {ip}"
            )

        elif exc.code == 429:
            print(
                f"    [!] AbuseIPDB : limite de requêtes "
                f"atteinte pour {ip}"
            )

        else:
            print(
                f"    [!] AbuseIPDB HTTP {exc.code} "
                f"pour {ip}"
            )

        return None

    except (
        TimeoutError,
        socket.timeout
    ):

        print(
            f"    [!] AbuseIPDB timeout pour {ip}"
        )

        return None

    except urllib.error.URLError as exc:

        print(
            f"    [!] Erreur réseau AbuseIPDB "
            f"pour {ip} : {exc}"
        )

        return None

    except json.JSONDecodeError:

        print(
            f"    [!] Réponse AbuseIPDB invalide "
            f"pour {ip}"
        )

        return None

    except Exception as exc:

        print(
            f"    [!] Exception AbuseIPDB pour "
            f"{ip} : {type(exc).__name__}: {exc}"
        )

        return None

    # ------------------------------------------------------------
    # Récupération du score
    # ------------------------------------------------------------

    data = result.get("data") or {}

    score = data.get(
        "abuseConfidenceScore",
        0
    )

    try:
        score = int(score)
    except (TypeError, ValueError):
        score = 0

    # Score trop faible => pas de finding
    if score < ABUSEIPDB_MIN_SCORE:
        return None

    print(
        f"    [!] AbuseIPDB : {ip} -> "
        f"score {score}/100"
    )

    return {
        "ip": ip,
        "confidence_score": score,
        "reference": (
            f"https://www.abuseipdb.com/check/{ip}"
        ),
    }

# ============================================================
# SCAN PRINCIPAL
# ============================================================

def scan():
    """Run configured passive threat-intelligence checks and save findings."""
    global _otx_consecutive_failures, _otx_disabled
    _otx_consecutive_failures = 0
    _otx_disabled = False

    active_sources = []

    if URLHAUS_AUTH_KEY:
        active_sources.append("URLhaus")

    if OTX_API_KEY:
        active_sources.append("OTX")

    if ABUSEIPDB_API_KEY:
        active_sources.append("AbuseIPDB")

    if not active_sources:
        print("[!] Aucune clé API configurée.")
    else:
        print(
            "[threat-intel] sources actives : "
            + ", ".join(active_sources)
        )

    if CURL_BIN:
        print(
            f"[threat-intel] curl détecté : {CURL_BIN}"
        )
    else:
        print(
            "[!] curl non détecté. OTX utilisera urllib."
        )

    subdomains = load_all_subdomains()

    print(
        f"[threat-intel] {len(subdomains)} sous-domaine(s) à vérifier"
    )

    findings = []

    for idx, (subdomain, domain) in enumerate(subdomains, start=1):

        details = {}

        # ----------------------------------------------------
        # URLHAUS
        # ----------------------------------------------------

        urlhaus_result = query_urlhaus(subdomain)

        if urlhaus_result:
            details["urlhaus"] = urlhaus_result

        if URLHAUS_AUTH_KEY:
            time.sleep(REQUEST_PAUSE)

        # ----------------------------------------------------
        # OTX
        # ----------------------------------------------------

        otx_result = query_otx(subdomain)

        if otx_result:
            details["otx"] = otx_result

        if OTX_API_KEY and not _otx_disabled:
            time.sleep(REQUEST_PAUSE)

        # ----------------------------------------------------
        # ABUSEIPDB
        # ----------------------------------------------------

        if ABUSEIPDB_API_KEY:

            ip = resolve_ip(subdomain)

            if ip:
                abuseipdb_result = query_abuseipdb(ip)

                if abuseipdb_result:
                    details["abuseipdb"] = abuseipdb_result

                time.sleep(REQUEST_PAUSE)

        # ----------------------------------------------------
        # FINDING
        # ----------------------------------------------------

        if details:

            finding = {
                "subdomain": subdomain,
                "domain": domain,
                "sources": sorted(details.keys()),
                "details": details,
            }

            findings.append(finding)

            print(
                f"    [!] {subdomain} -> signal(s) sur "
                f"{', '.join(sorted(details.keys()))}"
            )

        if idx % 10 == 0:
            print(
                f"    ... {idx}/{len(subdomains)} vérifiés"
            )

    # ========================================================
    # SAUVEGARDE
    # ========================================================

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(
            findings,
            f,
            indent=2,
            ensure_ascii=False
        )

    if _otx_disabled:
        print(
            "[!] Note : OTX a ete desactive en cours de scan suite a des "
            "echecs reseau repetes (voir plus haut) - les sous-domaines "
            "restants n'ont ete verifies que sur URLhaus/AbuseIPDB."
        )

    print(
        f"[OK] {len(findings)} sous-domaine(s) associé(s) "
        f"à une menace connue -> {OUTPUT_FILE}"
    )

    return findings


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    scan()
