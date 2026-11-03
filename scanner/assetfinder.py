import subprocess
import os

SCANS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scans")


def run_assetfinder(domain):
    output_file = os.path.join(SCANS_DIR, f"assetfinder_{domain}.txt")

    with open(output_file, "w") as f:
        subprocess.run(
            ["assetfinder", "--subs-only", domain],
            stdout=f,
            check=True
        )

    print(f"[+] Assetfinder saved: {output_file}")
    return output_file


if __name__ == "__main__":
    domains = [
        "sekera-group.com",
        "sec-dojo.com",
        "secdojo.com",
        "vincilogic.com",
        "vinci-logic.com",
    ]
    for d in domains:
        run_assetfinder(d)