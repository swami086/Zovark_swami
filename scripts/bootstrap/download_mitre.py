"""Download MITRE ATT&CK STIX bundle (enterprise-attack.json).

Run with internet access:
  python scripts/bootstrap/download_mitre.py
  OR: docker run --rm -v ./data/bootstrap:/data python:3.11-slim python -c "$(cat scripts/bootstrap/download_mitre.py)"
"""

import os
import urllib.request
import json

URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
OUT_DIR = os.environ.get("BOOTSTRAP_DIR", "data/bootstrap/mitre")
OUT_FILE = os.path.join(OUT_DIR, "enterprise-attack.json")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)

    if os.path.exists(OUT_FILE):
        size_mb = os.path.getsize(OUT_FILE) / (1024 * 1024)
        print(f"Already exists: {OUT_FILE} ({size_mb:.1f} MB)")
        return

    print(f"Downloading MITRE ATT&CK STIX bundle...")
    print(f"  URL: {URL}")
    urllib.request.urlretrieve(URL, OUT_FILE)
    size_mb = os.path.getsize(OUT_FILE) / (1024 * 1024)
    print(f"  Saved: {OUT_FILE} ({size_mb:.1f} MB)")

    # Quick sanity check
    with open(OUT_FILE, "r") as f:
        data = json.load(f)
    objects = data.get("objects", [])
    techniques = [o for o in objects if o.get("type") == "attack-pattern" and not o.get("revoked", False)]
    print(f"  Total objects: {len(objects)}")
    print(f"  Active techniques: {len(techniques)}")


if __name__ == "__main__":
    main()
