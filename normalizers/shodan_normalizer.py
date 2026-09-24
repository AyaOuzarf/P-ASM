"""
shodan_normalizer.py

Lit tous les fichiers scanner/scans/shodan_*.json (sortie brute de
scanner/shodan_scan.py) et les convertit vers un JSON normalise et lisible :
org, ISP, ports ouverts, vulns, services, etc. par IP.
"""
import glob
import json
import os
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANS_DIR = os.path.join(BASE_DIR, "scanner", "scans")
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shodan_normalized.json")


def normalize_host(raw: dict) -> dict:
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

    return {
        "ip": raw.get("ip_str"),
        "org": raw.get("org"),
        "isp": raw.get("isp"),
        "asn": raw.get("asn"),
        "country": raw.get("country_name"),
        "city": raw.get("city"),
        "hostnames": raw.get("hostnames", []),
        "domains": raw.get("domains", []),
        "open_ports": sorted(raw.get("ports", [])),
        "vulns": sorted(raw.get("vulns", [])) if raw.get("vulns") else [],
        "os": raw.get("os"),
        "last_update": raw.get("last_update"),
        "services": services,
    }


def parse_file(filepath: str) -> tuple[str, list[dict]]:
    with open(filepath, encoding="utf-8") as f:
        record = json.load(f)

    domain = record.get("domain", "")
    hosts = [normalize_host(raw) for raw in record.get("raw_hosts", [])]
    return domain, hosts


def normalize():
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
    