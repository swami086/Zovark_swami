"""
HYDRA VirusTotal Integration — Temporal Activity
Enriches IOCs (hashes, domains, IPs) via VirusTotal API v3.
"""
import os
import httpx
from temporalio import activity


VT_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"


@activity.defn
async def enrich_ioc_virustotal(data: dict) -> dict:
    """
    Enrich an IOC via VirusTotal.

    Args:
        data: {
            "ioc_type": "hash" | "domain" | "ip",
            "ioc_value": str,
            "api_key": optional override,
        }

    Returns:
        {"status": "enriched"|"skipped"|"error", "malicious": int, "suspicious": int, ...}
    """
    api_key = data.get("api_key") or VT_API_KEY
    if not api_key:
        return {"status": "skipped", "reason": "virustotal_not_configured"}

    ioc_type = data.get("ioc_type", "hash")
    ioc_value = data.get("ioc_value", "")

    endpoint_map = {
        "hash": f"{VT_BASE_URL}/files/{ioc_value}",
        "domain": f"{VT_BASE_URL}/domains/{ioc_value}",
        "ip": f"{VT_BASE_URL}/ip_addresses/{ioc_value}",
    }

    url = endpoint_map.get(ioc_type)
    if not url:
        return {"status": "error", "reason": f"unknown ioc_type: {ioc_type}"}

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers={"x-apikey": api_key})

            if resp.status_code == 200:
                result = resp.json().get("data", {}).get("attributes", {})
                stats = result.get("last_analysis_stats", {})
                return {
                    "status": "enriched",
                    "ioc_type": ioc_type,
                    "ioc_value": ioc_value,
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "reputation": result.get("reputation", 0),
                }
            elif resp.status_code == 404:
                return {"status": "not_found", "ioc_type": ioc_type, "ioc_value": ioc_value}
            else:
                return {"status": "error", "http_status": resp.status_code, "error": resp.text[:200]}
    except Exception as e:
        activity.logger.error("VirusTotal enrichment error", error=str(e))
        return {"status": "error", "error": str(e)}
