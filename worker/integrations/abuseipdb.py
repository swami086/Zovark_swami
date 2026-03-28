"""
ZOVARK AbuseIPDB Integration — Temporal Activity
Checks IP reputation via AbuseIPDB API v2.
"""
import os
import httpx
from temporalio import activity


ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"


@activity.defn
async def check_ip_reputation(data: dict) -> dict:
    """
    Check IP reputation via AbuseIPDB.

    Args:
        data: {
            "ip_address": str,
            "max_age_days": int (default 90),
            "api_key": optional override,
        }

    Returns:
        {"status": "checked"|"skipped"|"error", "abuse_confidence": int, ...}
    """
    api_key = data.get("api_key") or ABUSEIPDB_API_KEY
    if not api_key:
        return {"status": "skipped", "reason": "abuseipdb_not_configured"}

    ip_address = data.get("ip_address", "")
    max_age = data.get("max_age_days", 90)

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                f"{ABUSEIPDB_BASE_URL}/check",
                params={"ipAddress": ip_address, "maxAgeInDays": max_age, "verbose": ""},
                headers={"Key": api_key, "Accept": "application/json"},
            )

            if resp.status_code == 200:
                result = resp.json().get("data", {})
                return {
                    "status": "checked",
                    "ip_address": ip_address,
                    "abuse_confidence": result.get("abuseConfidenceScore", 0),
                    "country_code": result.get("countryCode", ""),
                    "isp": result.get("isp", ""),
                    "domain": result.get("domain", ""),
                    "is_tor": result.get("isTor", False),
                    "total_reports": result.get("totalReports", 0),
                    "is_whitelisted": result.get("isWhitelisted", False),
                }
            else:
                return {"status": "error", "http_status": resp.status_code, "error": resp.text[:200]}
    except Exception as e:
        activity.logger.error("AbuseIPDB check error", error=str(e))
        return {"status": "error", "error": str(e)}
