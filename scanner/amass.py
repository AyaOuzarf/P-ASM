"""
amass.py - lance Amass en mode strictement passif sur les domaines du
perimetre et sauvegarde une sortie brute .txt par domaine dans scans/ a la racine.

Mode -passive : aucune requete n'est envoyee a la cible elle-meme, seules des
sources tierces sont interrogees (resolveurs DNS publics, bases de certificats).

Necessite Amass installe (go install github.com/owasp-amass/amass/v4/...@master)
"""
"""E-ASM Amass collector: runs passive domain enumeration."""

import subprocess
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCANS_DIR = os.path.join(os.path.dirname(BASE_DIR), "scans")

DOMAINS = [
    "sekera-group.com",
    "sec-dojo.com",
    "secdojo.com",
    "vincilogic.com",
    "vinci-logic.com",
]

TIMEOUT_SECONDS = 300  # Amass -passive peut etre lent selon le domaine


def run():
    """Run passive Amass enumeration for every configured domain."""
    for domain in DOMAINS:
        out_file = os.path.join(SCANS_DIR, f"amass_{domain}.txt")
        print(f"[*] Amass (-passive) -> {domain}")
        try:
            result = subprocess.run(
                ["amass", "enum", "-passive", "-d", domain],
                check=True, timeout=TIMEOUT_SECONDS, capture_output=True, text=True,
            )
            with open(out_file, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            n_lines = len([l for l in result.stdout.splitlines() if l.strip()])
            print(f"    -> {n_lines} ligne(s) ecrite(s) dans {out_file}")
        except FileNotFoundError:
            print("[!] amass introuvable. Installe-le avec :")
            print("    go install github.com/owasp-amass/amass/v4/...@master")
            return
        except subprocess.TimeoutExpired:
            print(f"[!] Timeout ({TIMEOUT_SECONDS}s) depasse pour {domain}, domaine ignore.")
            continue
        except subprocess.CalledProcessError as e:
            print(f"[!] Erreur Amass sur {domain} : {e}")
            continue


if __name__ == "__main__":
    run()
