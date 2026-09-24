"""
subfinder.py - lance Subfinder sur les domaines du perimetre et sauvegarde
une sortie brute .txt par domaine dans scanner/scans/.

Necessite Subfinder installe (go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)
"""
import subprocess
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
SCANS_DIR = os.path.join(BASE_DIR, "scans")

DOMAINS = [
    "sekera-group.com",
    "sec-dojo.com",
    "secdojo.com",
    "vincilogic.com",
    "vinci-logic.com",
]


def run():
    os.makedirs(SCANS_DIR, exist_ok=True)
    for domain in DOMAINS:
        out_file = os.path.join(SCANS_DIR, f"subfinder_{domain}.txt")
        print(f"[*] Subfinder -> {domain}")
        try:
            subprocess.run(
                ["subfinder", "-d", domain, "-o", out_file],
                check=True, timeout=120,
            )
        except FileNotFoundError:
            print("[!] subfinder introuvable. Installe-le avec :")
            print("    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")
            return
        except subprocess.CalledProcessError as e:
            print(f"[!] Erreur Subfinder sur {domain} : {e}")


if __name__ == "__main__":
    run()
