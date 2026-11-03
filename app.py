"""
app.py - Dashboard Pentest/Recon (version simplifiee, sans SOC/IA)

Lit les fichiers JSON normalises (subfinder / amass / certs), fusionne les
doublons, categorise par mot-cle, calcule un score de risque, verifie la
disponibilite reelle de chaque hote, et affiche le tout dans un dashboard.
Les ports ouverts restent optionnels et ne depandent pas d'un outil exterieur
au projet.
"""
import json
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

from flask import Flask, render_template, abort, Response, request, send_from_directory
from datetime import datetime, timezone

from risk_engine import compute_verifiable_risk, calculate_enterprise_risk
from ai_helper import build_ai_summary, build_local_summary
from vulnerability_sources import collect_verified_findings

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
NORMALIZERS_DIR = os.path.join(BASE_DIR, "normalizers")

SOURCE_FILES = {
    "subfinder": "subfinder_normalized.json",
    "amass": "amass_normalized.json",
    "assetfinder": "assetfinder_normalized.json",
}

CERTS_FILE = "certs_normalized.json"
TAKEOVER_FILE = "takeover_findings.json"
CVE_FILE = "cve_findings.json"  # produit par cve_scanner.py, a la racine (pas dans normalizers/)

ALL_DISCOVERY_SOURCES = set(SOURCE_FILES) | {"certs"}

# The project is intentionally passive-first for enterprise use.
# Active HTTP probing is optional and disabled by default because the project is
# meant to provide evidence-based risk scoring from public, non-intrusive signals.
PASSIVE_ONLY_MODE = os.environ.get("EASM_PASSIVE_ONLY", "true").lower() == "true"
ENABLE_AI_SUMMARY = os.environ.get("ENABLE_AI_SUMMARY", "false").lower() == "true"
ENABLE_LIVE_VULN_LOOKUPS = os.environ.get("ENABLE_LIVE_VULN_LOOKUPS", "false").lower() == "true"

LIVENESS_TIMEOUT = 3
LIVENESS_MAX_WORKERS = 20

app = Flask(__name__)


# ---------------------------------------------------------------------------
# Chargement + fusion des sources JSON
# ---------------------------------------------------------------------------
def load_source(filename):
    """Load one normalized JSON source file."""
    filepath = os.path.join(NORMALIZERS_DIR, filename)
    if not os.path.exists(filepath):
        return []
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


def load_all_records():
    """Load discovery records from all dashboard-connected sources."""
    all_records = []
    for source, filename in SOURCE_FILES.items():
        all_records.extend(load_source(filename))
    return all_records


def load_certs_data():
    """Load normalized certificate summaries when available."""
    filepath = os.path.join(NORMALIZERS_DIR, CERTS_FILE)
    if not os.path.exists(filepath):
        return {"by_domain": {}, "by_subdomain": {}}
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


def load_takeover_data():
    """Load takeover findings indexed by subdomain."""
    filepath = os.path.join(NORMALIZERS_DIR, TAKEOVER_FILE)
    if not os.path.exists(filepath):
        return {}
    with open(filepath, encoding="utf-8") as f:
        findings = json.load(f)
    return {finding["subdomain"]: finding for finding in findings}


def load_cve_data():
    """Retourne {host: [{"port":.., "service":.., "banner":.., "matched_query":..,
    "cves": [{"cve_id":.., "cvss_score":.., "cvss_severity":.., "description":..}, ...]}, ...]}
    depuis cve_findings.json (produit par cve_scanner.py), ou {} si pas encore genere."""
    filepath = os.path.join(BASE_DIR, CVE_FILE)
    if not os.path.exists(filepath):
        return {}
    with open(filepath, encoding="utf-8") as f:
        return json.load(f)


def merge_by_subdomain(records, certs_by_subdomain):
    """Merge discovery and certificate records by hostname."""
    merged = {}
    for r in records:
        sub = r["subdomain"]
        if sub not in merged:
            merged[sub] = {
                "subdomain": sub,
                "domain": r["domain"],
                "sources": set(),
                "certificate": None,
            }
        merged[sub]["sources"].add(r["source"])

    for sub, cert_entry in certs_by_subdomain.items():
        if sub not in merged:
            merged[sub] = {
                "subdomain": sub,
                "domain": cert_entry.get("domain"),
                "sources": set(),
                "certificate": None,
            }
        merged[sub]["sources"].add("certs")
        merged[sub]["certificate"] = {
            "issuers": cert_entry.get("issuers", []),
            "active": cert_entry.get("active", False),
            "soonest_expiry": cert_entry.get("soonest_expiry"),
        }

    return merged


# ---------------------------------------------------------------------------
# Ports ouverts : optionnels, sans dependance a un outil externe au projet
# ---------------------------------------------------------------------------
def load_ports_by_host():
    """Retourne une liste vide par defaut.

    Le projet ne depend plus d'une base asm_inventory.db ou d'un outil externe
    non present dans ce depot. Les ports peuvent donc etre ajoutes plus tard
    par une autre source locale si besoin.
    """
    return {}


# ---------------------------------------------------------------------------
# Liveness check HTTP
# ---------------------------------------------------------------------------
def check_alive(subdomain, timeout=LIVENESS_TIMEOUT):
    """Perform an optional HTTP HEAD liveness check for one hostname."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            req = Request(url, method="HEAD", headers={"User-Agent": "pentest-recon/1.0"})
            with urlopen(req, timeout=timeout) as resp:
                return True, resp.status, scheme
        except HTTPError as e:
            return True, e.code, scheme
        except (URLError, TimeoutError, OSError):
            continue
    return False, None, None


def check_all_alive(subdomains):
    """Run liveness checks concurrently for a collection of hostnames."""
    results = {}
    with ThreadPoolExecutor(max_workers=LIVENESS_MAX_WORKERS) as executor:
        futures = {executor.submit(check_alive, sub): sub for sub in subdomains}
        for future in as_completed(futures):
            sub = futures[future]
            try:
                alive, status, scheme = future.result()
            except Exception:
                alive, status, scheme = False, None, None
            results[sub] = {"alive": alive, "status": status, "scheme": scheme}
    return results


# ---------------------------------------------------------------------------
# Categorisation (par mot-cle dans le nom)
# ---------------------------------------------------------------------------
CATEGORY_RULES = [
    (r"^(login|auth|account|sso|bo-login)\.", "Access / authentication"),
    (r"^bo-", "Back office / administration"),
    (r"^(vpn)\.", "Remote access"),
    (r"^(staging|stg|dev|test|preprod)", "Pre-production"),
    (r"^(grafana|prometheus|sentry)\.", "Monitoring / observability"),
    (r"^(gitlab|registry)\.", "Infrastructure / DevOps"),
    (r"^(odoo)\.", "ERP / business management"),
    (r"^(ns1?|ip|wildcard)\.", "DNS / IP infrastructure"),
]


def categorize(subdomain):
    """Assign a business-oriented category from hostname naming patterns."""
    for pattern, category in CATEGORY_RULES:
        if re.search(pattern, subdomain):
            return category
    return "Other"


# ---------------------------------------------------------------------------
# Scoring de risque (Exposition x Sensibilite, base sur le nom)
# ---------------------------------------------------------------------------
RISK_RULES = [
    (r"^vpn\.",                          3, 3, "Potential remote access point to internal infrastructure"),
    (r"^gitlab\.",                       3, 3, "May host source code, secrets, or access tokens"),
    (r"^bo-",                            2, 3, "Back-office or administration interface"),
    (r"^odoo\.",                         2, 3, "ERP containing business data"),
    (r"^registry\.",                     2, 2, "Package or image registry; risk if private images are exposed"),
    (r"^(grafana|prometheus)\.",         2, 2, "Monitoring dashboard; risk if anonymous access is enabled"),
    (r"^sentry\.",                       2, 2, "Error traces may contain internal information"),
    (r"^(staging|stg|dev|test|preprod)", 3, 1, "Publicly exposed pre-production environment"),
    (r"^(login|auth|account|sso)\.",     3, 2, "Exposed authentication endpoint"),
]

DEFAULT_EXPO, DEFAULT_SENS, DEFAULT_JUSTIF = 1, 1, "Standard subdomain; no sensitive naming pattern detected"


def score_asset(subdomain):
    """Return the initial exposure, sensitivity and explanation for an asset."""
    for pattern, expo, sens, justif in RISK_RULES:
        if re.search(pattern, subdomain):
            return expo, sens, justif
    return DEFAULT_EXPO, DEFAULT_SENS, DEFAULT_JUSTIF


def risk_label(score):
    """Convert a numeric score into a dashboard risk label."""
    if score >= 9:
        return "Critical"
    if score >= 6:
        return "High"
    if score >= 3:
        return "Medium"
    return "Low"


def risk_color(score):
    """Convert a numeric score into a Bootstrap dashboard color."""
    if score >= 9:
        return "danger"
    if score >= 6:
        return "warning"
    if score >= 3:
        return "info"
    return "success"


# ---------------------------------------------------------------------------
# Construction de la liste d'actifs
# ---------------------------------------------------------------------------
def cvss_to_risk_score(cvss_score):
    """Convertit un score CVSS (0-10) vers l'echelle de risque du dashboard
    (1-9, meme echelle que expo x sens) pour rester comparable. Mapping
    volontairement simple : CVSS est deja une echelle de gravite reconnue,
    on se contente de la ramener au meme intervalle plutot que d'inventer
    une nouvelle ponderation."""
    if cvss_score is None:
        return None
    return max(1, min(9, round(cvss_score * 0.9)))


def build_assets(with_liveness=None):
    """Build the asset list using evidence-based risk scoring.

    The project defaults to passive mode for enterprise safety. Active probing is
    still available as an optional flag but is not required for normal operation.
    """
    if with_liveness is None:
        with_liveness = not PASSIVE_ONLY_MODE

    records = load_all_records()
    certs_data = load_certs_data()
    takeover_data = load_takeover_data()
    cve_data = load_cve_data()
    merged = merge_by_subdomain(records, certs_data.get("by_subdomain", {}))
    ports_by_host = load_ports_by_host()

    liveness = check_all_alive(merged.keys()) if with_liveness else {}

    assets = []
    for idx, (subdomain, data) in enumerate(sorted(merged.items()), start=1):
        expo, sens, base_justif = score_asset(subdomain)
        live_info = liveness.get(subdomain, {"alive": None, "status": None, "scheme": None})

        takeover = takeover_data.get(subdomain)
        cve_entries = cve_data.get(subdomain, [])
        cert_info = data.get("certificate")

        # This is the new risk engine: we keep a base score from the naming pattern,
        # but we permit a stronger score only when there is real evidence such as a
        # takeover risk, an expired certificate, or a real CVE tied to the asset.
        # The verified vulnerability layer adds additional public intelligence and
        # enriches the CVE data when the project learns the software family of the
        # host or the banner of the service.
        risk = compute_verifiable_risk(
            subdomain=subdomain,
            base_exposure=expo,
            base_sensitivity=sens,
            base_justification=base_justif,
            takeover=takeover,
            cve_findings=cve_entries,
            cert_info=cert_info,
        )

        # Enrich with public/verified vulnerability records for the asset, when the
        # project can infer technology hints from the subdomain or service names.
        service_names = [p.get("service") for p in ports_by_host.get(subdomain, []) if p.get("service")]
        verified_cves = (
            collect_verified_findings(subdomain, service_names)
            if ENABLE_LIVE_VULN_LOOKUPS
            else []
        )
        score = risk["score"]
        justif = risk["reason"]

        if verified_cves:
            verified_cvss = max((item.get("cvss_score") for item in verified_cves if item.get("cvss_score") is not None), default=None)
            if verified_cvss is not None:
                verified_score = max(1, min(9, round(float(verified_cvss) * 0.9)))
                if verified_score > score:
                    score = verified_score
                    justif = (
                        f"{justif} | VERIFIED PUBLIC VULNERABILITY: "
                        f"{verified_cves[0]['cve_id']} (CVSS {verified_cvss}) "
                        f"from NVD / EPSS / KEV - {verified_cves[0].get('description', '')[:150]}"
                    )

        # The enterprise risk formula is the final authoritative score. It combines
        # business criticality, public exposure, verified CVE severity, and evidence
        # from KEV/EPSS, while preserving the explainability of the legacy risk notes.
        enterprise_risk = calculate_enterprise_risk(
            subdomain=subdomain,
            asset_criticality=max(1, min(5, expo + sens - 1)),
            exposure=max(1, min(5, expo)),
            verified_cves=verified_cves,
            takeover_risk=takeover,
            cert_active=cert_info.get("active") if cert_info else None,
        )
        score = min(10, max(1, enterprise_risk["score"]))
        justif = f"{enterprise_risk['justification']} | {justif}"

        confidence = round(len(data["sources"]) / len(ALL_DISCOVERY_SOURCES) * 100)

        is_shadow = len(data["sources"]) == 1 and (
            live_info["alive"] is False
            or (data["certificate"] and not data["certificate"]["active"])
        )

        asset = {
            "id": idx,
            "subdomain": subdomain,
            "root_domain": data["domain"],
            "category": categorize(subdomain),
            "alive": live_info["alive"],
            "http_status": live_info["status"],
            "scheme": live_info["scheme"],
            "ports": ports_by_host.get(subdomain, []),
            "exposition": expo,
            "sensibilite": sens,
            "score": score,
            "risk_label": risk_label(score),
            "risk_color": risk_color(score),
            "priority": enterprise_risk["priority"],
            "notes": justif,
            "sources": sorted(data["sources"]),
            "confidence": confidence,
            "is_shadow": is_shadow,
            "certificate": data["certificate"],
            "cert_only": data["sources"] == {"certs"},
            "takeover_risk": takeover,
            "cve_findings": cve_entries,
            "verified_vulns": verified_cves,
            "risk_evidence": risk["sources"],
        }

        if ENABLE_AI_SUMMARY:
            # The AI layer is optional and works through a free API endpoint when a
            # user provides an API key. If no key is set, the helper falls back to a
            # local summary instead of failing the app.
            asset["ai_summary"] = build_ai_summary(asset)
        else:
            # Keep the assistant section visible even when external AI is disabled.
            # This local explanation uses only the evidence already calculated by
            # the application and never sends asset data outside the project.
            asset["ai_summary"] = build_local_summary(asset)
            asset["ai_remote_enabled"] = False

        if ENABLE_AI_SUMMARY:
            asset["ai_remote_enabled"] = True

        assets.append(asset)

    return assets


def build_stats(assets):
    """Calculate dashboard statistics for the supplied asset list."""
    total = len(assets)
    alive = sum(1 for a in assets if a["alive"] is True)
    critical = sum(1 for a in assets if a["risk_label"] == "Critical")
    high = sum(1 for a in assets if a["risk_label"] == "High")
    with_open_ports = sum(1 for a in assets if a["ports"])
    cert_only = sum(1 for a in assets if a["cert_only"])
    expired_certs = sum(1 for a in assets if a["certificate"] and not a["certificate"]["active"])
    takeover_risks = sum(1 for a in assets if a["takeover_risk"])
    shadow_assets = sum(1 for a in assets if a["is_shadow"])
    with_cve = sum(1 for a in assets if a["cve_findings"])

    comparison = {}
    for a in assets:
        dom = a["root_domain"]
        comparison.setdefault(dom, {"subfinder": 0, "amass": 0, "assetfinder": 0, "certs": 0})
        for src in a["sources"]:
            if src in comparison[dom]:
                comparison[dom][src] += 1

    raw_records = load_all_records()
    by_source_raw = {}
    for r in raw_records:
        by_source_raw.setdefault(r["source"], 0)
        by_source_raw[r["source"]] += 1
    certs_data = load_certs_data()
    by_source_raw["certs"] = len(certs_data.get("by_subdomain", {}))

    confirmed_multi = sum(1 for a in assets if len(a["sources"]) >= 2)

    return {
        "total": total,
        "alive": alive,
        "critical": critical,
        "high": high,
        "with_open_ports": with_open_ports,
        "cert_only": cert_only,
        "expired_certs": expired_certs,
        "takeover_risks": takeover_risks,
        "shadow_assets": shadow_assets,
        "with_cve": with_cve,
        "comparison": comparison,
        "by_source_raw": by_source_raw,
        "confirmed_multi": confirmed_multi,
    }


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    """Render the filtered asset inventory dashboard."""
    assets = build_assets()
    filters = {
        "search": request.args.get("search", "").strip().lower(),
        "category": request.args.get("category", "all"),
        "priority": request.args.get("priority", "all"),
        "status": request.args.get("status", "all"),
        "domain": request.args.get("domain", "all"),
    }

    filtered_assets = []
    for asset in assets:
        if filters["search"]:
            haystack = f"{asset['subdomain']} {asset['root_domain']} {asset['category']}".lower()
            if filters["search"] not in haystack:
                continue
        if filters["category"] != "all" and asset["category"] != filters["category"]:
            continue
        if filters["priority"] != "all" and asset.get("priority") != filters["priority"]:
            continue
        if filters["status"] != "all":
            status = "alive" if asset["alive"] is True else "down" if asset["alive"] is False else "unknown"
            if status != filters["status"]:
                continue
        if filters["domain"] != "all" and asset["root_domain"] != filters["domain"]:
            continue
        filtered_assets.append(asset)

    stats = build_stats(filtered_assets)
    categories = sorted({a["category"] for a in assets})
    domains = sorted({a["root_domain"] for a in assets})
    priorities = ["P1", "P2", "P3", "P4"]
    return render_template("index.html", assets=filtered_assets, stats=stats, filters=filters, categories=categories, domains=domains, priorities=priorities)


@app.route("/brand/sekera.png")
def sekera_logo():
    """Serve the Sekera Group brand image."""
    logo_path = os.path.join(BASE_DIR, "templates", "sekera.png")
    if not os.path.isfile(logo_path):
        abort(404)
    return send_from_directory(os.path.join(BASE_DIR, "templates"), "sekera.png")


@app.route("/methodology")
def methodology():
    """Render the methodology and public-source catalog page."""
    source_catalog = [
        {
            "name": "Subfinder",
            "purpose": "Passive subdomain discovery",
            "url": "https://github.com/projectdiscovery/subfinder",
            "type": "Discovery",
        },
        {
            "name": "Amass",
            "purpose": "Passive discovery and attack-surface analysis",
            "url": "https://github.com/OWASP/Amass",
            "type": "Discovery",
        },
        {
            "name": "Assetfinder",
            "purpose": "Fast subdomain discovery",
            "url": "https://github.com/tomnomnom/assetfinder",
            "type": "Discovery",
        },
        {
            "name": "crt.sh",
            "purpose": "TLS certificate history and public subdomains",
            "url": "https://crt.sh/",
            "type": "Certificate",
        },
        {
            "name": "Cert Spotter",
            "purpose": "Public certificate transparency",
            "url": "https://sslmate.com/certspotter/",
            "type": "Certificate",
        },
        {
            "name": "NVD",
            "purpose": "CVE / CVSS / description officielle",
            "url": "https://nvd.nist.gov/",
            "type": "Vulnerability",
        },
        {
            "name": "CISA KEV",
            "purpose": "Known exploited vulnerabilities",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "type": "Vulnerability",
        },
        {
            "name": "EPSS",
            "purpose": "Exploit likelihood and prioritization",
            "url": "https://www.first.org/epss/",
            "type": "Vulnerability",
        },
        {
            "name": "OSV",
            "purpose": "Open-source package vulnerabilities",
            "url": "https://osv.dev/",
            "type": "Vulnerability",
        },
        {
            "name": "Takeover detector",
            "purpose": "Passive subdomain takeover risk detection",
            "url": "https://github.com/EdOverflow/can-i-take-over-xyz",
            "type": "Detection",
        },
    ]
    return render_template("methodology.html", sources=source_catalog)


@app.route("/asset/<int:asset_id>")
def asset_detail(asset_id):
    """Render detailed evidence and scoring for one asset."""
    assets = build_assets()
    asset = next((a for a in assets if a["id"] == asset_id), None)
    if asset is None:
        abort(404)
    return render_template("asset.html", asset=asset)


@app.route("/export.json")
def export_json():
    """Export the current asset inventory and statistics as JSON."""
    assets = build_assets()
    stats = build_stats(assets)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "stats": stats,
        "assets": assets,
    }
    body = json.dumps(payload, indent=2, ensure_ascii=False)
    return Response(
        body,
        mimetype="application/json",
        headers={"Content-Disposition": "attachment; filename=recon_export.json"},
    )


if __name__ == "__main__":
    debug_mode = os.environ.get("EASM_DEBUG", "true").lower() == "true"
    host = os.environ.get("EASM_HOST", "127.0.0.1")
    if host != "127.0.0.1" and debug_mode:
        raise RuntimeError(
            "Refuse de lancer avec debug=True sur un host reseau. "
            "Mets EASM_DEBUG=false pour exposer le dashboard sur le reseau."
        )
    app.run(debug=debug_mode, host=host, port=int(os.environ.get("EASM_PORT", 5000)))
