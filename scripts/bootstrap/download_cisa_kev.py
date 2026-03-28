"""Download CISA Known Exploited Vulnerabilities (KEV) catalog.

Run with internet access:
  python scripts/bootstrap/download_cisa_kev.py
"""

import os
import urllib.request
import json

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
OUT_DIR = os.environ.get("BOOTSTRAP_DIR", "data/bootstrap/cisa")
OUT_FILE = os.path.join(OUT_DIR, "known_exploited_vulnerabilities.json")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    if os.path.exists(OUT_FILE):
        size_mb = os.path.getsize(OUT_FILE) / (1024 * 1024)
        print(f"Already exists: {OUT_FILE} ({size_mb:.1f} MB)")
        return

    print(f"Downloading CISA KEV catalog...")
    print(f"  URL: {URL}")
    req = urllib.request.Request(URL, headers={"User-Agent": "ZOVARK-Bootstrap/1.0"})
    with urllib.request.urlopen(req) as resp:
        data = resp.read()
    with open(OUT_FILE, "wb") as f:
        f.write(data)
    size_mb = len(data) / (1024 * 1024)
    print(f"  Saved: {OUT_FILE} ({size_mb:.1f} MB)")

    # Quick sanity check
    parsed = json.loads(data)
    vulns = parsed.get("vulnerabilities", [])
    print(f"  Total vulnerabilities: {len(vulns)}")


if __name__ == "__main__":
    main()
