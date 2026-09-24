import os
import re
import json
import glob
from datetime import datetime, timezone

SCANS_DIR = os.path.join(os.path.dirname(__file__), "..", "scans")
OUTPUT_FILE = os.path.join(os.path.dirname(__file__), "assetfinder_normalized.json")

SUBDOMAIN_RE = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9-]{1,63})+$")


def is_valid_subdomain(line):
    line = line.strip().lower()
    return bool(line) and bool(SUBDOMAIN_RE.match(line))


def extract_domain_from_filename(filename):
    # assetfinder_sekera-group.com.txt -> sekera-group.com
    name = os.path.basename(filename)
    name = name.replace("assetfinder_", "").replace(".txt", "")
    return name


def normalize_file(filepath):
    domain = extract_domain_from_filename(filepath)
    records = []
    with open(filepath, "r", errors="ignore") as f:
        for line in f:
            sub = line.strip().lower()
            if is_valid_subdomain(sub):
                records.append({
                    "domain": domain,
                    "subdomain": sub,
                    "source": "assetfinder",
                    "discovered_at": datetime.now(timezone.utc).isoformat()
                })
    return records


def main():
    all_records = []
    files = glob.glob(os.path.join(SCANS_DIR, "assetfinder_*.txt"))

    for filepath in files:
        records = normalize_file(filepath)
        all_records.extend(records)
        print(f"[+] {os.path.basename(filepath)}: {len(records)} subdomains")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(all_records, f, indent=2)

    print(f"\n[+] Wrote {len(all_records)} total records to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()