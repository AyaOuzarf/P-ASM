"""
shodan_normalizer.py

Lit les fichiers scans/shodan_*.json produits par scanner/shodan_scanner.py
et convertit ses resultats (matches) en JSON normalise. Les fichiers Shodan
plus complets au format raw_hosts restent egalement acceptes.
"""
import glob
import json
import os
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANS_DIR = os.path.join(BASE_DIR, "scans")
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shodan_normalized.json")


def normalize_host(raw: dict) -> dict:
    """Convert one Shodan host record to the project schema."""
    services = []
    for item in raw.get("data", []):
        services.append({
            "port": item.get("port"),
            "transport": item.get("transport"),
            "product": item.get("product"),
            "version": item.get("version"),
            "cpe": item.get("cpe", []),
            "timestamp": item.get("timestamp"),
        })

    ports = set(raw.get("ports", []))
    if raw.get("port") is not None:
        ports.add(raw["port"])
    location = raw.get("location") or {}

    return {
        "ip": raw.get("ip_str") or raw.get("ip"),
        "org": raw.get("org"),
        "isp": raw.get("isp"),
        "asn": raw.get("asn"),
        "country": raw.get("country_name") or location.get("country"),
        "city": raw.get("city") or location.get("city"),
        "hostnames": raw.get("hostnames", []),
        "domains": raw.get("domains", []),
        "open_ports": sorted(ports),
        "vulns": sorted(raw.get("vulns", [])) if raw.get("vulns") else [],
        "os": raw.get("os"),
        "last_update": raw.get("last_update"),
        "services": services,
    }


def parse_file(filepath: str) -> tuple[str, list[dict]]:
    """Read a collector file and return its domain and normalized hosts."""
    with open(filepath, encoding="utf-8") as f:
        record = json.load(f)

    domain = record.get("domain", "")
    raw_hosts = record.get("raw_hosts")
    if raw_hosts is None:
        raw_hosts = record.get("matches", [])
    hosts = [normalize_host(raw) for raw in raw_hosts]
    return domain, hosts


def normalize():
    """Normalize all saved Shodan collector files."""
    now = datetime.now(timezone.utc).isoformat()
    normalized = {}

    for filepath in sorted(glob.glob(os.path.join(SCANS_DIR, "shodan_*.json"))):
        domain, hosts = parse_file(filepath)
        if not domain:
            print(f"[!] Fichier ignore (pas de champ 'domain'): {filepath}")
            continue

        normalized[domain] = {
            "hosts": hosts,
            "normalized_at": now,
        }
        print(f"[Shodan] {domain} -> {len(hosts)} hote(s)")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(normalized, f, indent=2, ensure_ascii=False)

    total = sum(len(v["hosts"]) for v in normalized.values())
    print(f"[✓] {total} hote(s) au total -> {OUTPUT_FILE}")
    return normalized


if __name__ == "__main__":
    normalize()
