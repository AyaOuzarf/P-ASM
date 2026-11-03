"""
snapshot_scan.py

Sauvegarde un instantane (snapshot) horodate de l'etat actuel de la surface
d'attaque (issu des normalizers deja generes : subfinder/amass/certs +
takeover_findings) dans normalizers/history/. A lancer manuellement apres
chaque cycle de scan complet (comme les autres normalizers), par exemple :

    python scanner\\subfinder.py
    python scanner\\amass.py
    python scanner\\certs.py
    python normalizers\\subfinder_normalizer.py
    python normalizers\\amass_normalizer.py
    python normalizers\\certs_normalizer.py
    python normalizers\\takeover_detector.py
    python normalizers\\snapshot_scan.py      <-- a la fin, une fois tout normalise

Ces snapshots horodates conservent des photos successives de la surface
connue. Le dashboard ne possede pas actuellement de route /drift; les
changements entre deux fichiers doivent donc etre compares separement.
"""
import json
import os
import sys
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HISTORY_DIR = os.path.join(BASE_DIR, "normalizers", "history")

# Permet d'importer build_assets() depuis app.py (a la racine du projet)
# sans dupliquer toute la logique de fusion/scoring ici.
sys.path.insert(0, BASE_DIR)
from app import build_assets  # noqa: E402


def take_snapshot():
    os.makedirs(HISTORY_DIR, exist_ok=True)

    # with_liveness=False : le drift porte sur la decouverte et les
    # certificats, pas sur la disponibilite HTTP instantanee (trop volatile
    # d'un scan a l'autre pour etre un signal de changement de surface utile,
    # et ca evite de refaire des centaines de requetes juste pour un snapshot).
    assets = build_assets(with_liveness=False)

    now = datetime.now(timezone.utc)
    snapshot = {
        "timestamp": now.isoformat(),
        "subdomains": {
            a["subdomain"]: {
                "domain": a["root_domain"],
                "sources": a["sources"],
                "certificate": a["certificate"],
                "takeover_risk": bool(a["takeover_risk"]),
            }
            for a in assets
        },
    }

    filename = f"snapshot_{now.strftime('%Y%m%dT%H%M%SZ')}.json"
    filepath = os.path.join(HISTORY_DIR, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False)

    print(f"[OK] Snapshot de {len(snapshot['subdomains'])} sous-domaine(s) -> {filepath}")
    return filepath


if __name__ == "__main__":
    take_snapshot()