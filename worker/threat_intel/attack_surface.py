"""External threat intelligence enrichment — attack surface reconnaissance.

Enriches IoCs (IPs, domains) with external intelligence:
subdomains, open ports, services, cloud exposure, risk scoring.

All HTTP requests go through the egress proxy (v0.12.0 requirement).

When ZOVARK_THREAT_INTEL_ENABLED is false (default), enrichment returns immediately
without calling outbound APIs (air-gap). When the investigation circuit breaker
is RED, external enrichment is skipped to shed load.
"""
import os
import json
import logging
from typing import Dict, List, Optional

from temporalio import activity

logger = logging.getLogger(__name__)

try:
    from settings import settings as _z_settings
except ImportError:
    _z_settings = None

REDHUNT_API_KEY = os.environ.get("REDHUNT_API_KEY", "")
REDHUNT_BASE_URL = "https://devapi.redhuntlabs.com/community/v1"

DANGEROUS_PORTS = {21, 23, 445, 3306, 3389, 5432, 5900, 6379, 8080, 27017}


class AttackSurfaceRecon:
    """External attack surface reconnaissance via threat intelligence APIs."""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or REDHUNT_API_KEY
        self._egress = None

    def _get_egress(self):
        if self._egress is None:
            from egress_controller import get_egress_controller
            self._egress = get_egress_controller()
        return self._egress

    async def enrich_ioc(self, ioc: str, ioc_type: str) -> Dict:
        """Enrich an IoC with external intelligence.

        Args:
            ioc: The indicator value (IP address, domain, etc.)
            ioc_type: One of 'ip', 'domain', 'url'

        Returns:
            Enrichment data with subdomains, ports, services, risk_score
        """
        if _z_settings is not None:
            ti_on = bool(_z_settings.threat_intel_enabled)
        else:
            ti_on = os.environ.get("ZOVARK_THREAT_INTEL_ENABLED", "false").lower() in (
                "1", "true", "yes"
            )

        if not ti_on:
            return self._empty_enrichment(
                ioc, "Threat intel disabled (ZOVARK_THREAT_INTEL_ENABLED=false, default air-gap)"
            )

        try:
            from stages.circuit_breaker import get_state

            if get_state() == "RED":
                return self._empty_enrichment(ioc, "Circuit breaker RED — external enrichment skipped")
        except Exception:
            pass

        if not self.api_key:
            return self._empty_enrichment(ioc, "No API key configured")

        if ioc_type not in ("ip", "domain"):
            return self._empty_enrichment(ioc, f"Unsupported IoC type: {ioc_type}")

        try:
            egress = self._get_egress()
            url = f"{REDHUNT_BASE_URL}/reconnaissance"
            result = await egress.request("GET", url, headers={
                "X-API-KEY": self.api_key,
                "Accept": "application/json",
            }, params={"query": ioc, "type": ioc_type}, timeout=15)

            if result.get("status") == 200:
                data = result.get("body", {})
                return self._parse_enrichment(ioc, data)
            else:
                return self._empty_enrichment(ioc, f"API returned {result.get('status')}")

        except Exception as e:
            logger.warning(f"Attack surface enrichment failed for {ioc}: {e}")
            return self._empty_enrichment(ioc, str(e))

    def _parse_enrichment(self, ioc: str, data: Dict) -> Dict:
        """Parse API response into standardized enrichment format."""
        subdomains = data.get("subdomains", [])
        ports = data.get("open_ports", [])
        services = data.get("services", [])
        cloud = data.get("cloud_assets", [])

        risk_score = self._calculate_risk(ports, services, cloud)

        return {
            "ioc": ioc,
            "subdomains": subdomains[:50],
            "open_ports": ports,
            "services": services,
            "cloud_exposure": cloud,
            "risk_score": round(risk_score, 2),
            "enriched": True,
        }

    def _calculate_risk(self, ports: List, services: List, cloud: List) -> float:
        """Calculate risk score from enrichment data."""
        score = 0.0
        # Exposed services
        score += min(len(services) * 0.1, 0.5)
        # Cloud assets
        if cloud:
            score += 0.2
        # Dangerous ports
        port_numbers = set()
        for p in ports:
            if isinstance(p, (int, float)):
                port_numbers.add(int(p))
            elif isinstance(p, dict):
                port_numbers.add(int(p.get("port", 0)))
        if port_numbers & DANGEROUS_PORTS:
            score += 0.3
        return min(score, 1.0)

    def _empty_enrichment(self, ioc: str, reason: str) -> Dict:
        return {
            "ioc": ioc,
            "subdomains": [], "open_ports": [], "services": [],
            "cloud_exposure": [], "risk_score": 0.0,
            "enriched": False, "reason": reason,
        }


@activity.defn
async def enrich_alert_with_attack_surface(params: dict) -> dict:
    """Temporal activity: enrich alert IoCs with attack surface data.

    Args: {alert_id: str, tenant_id: str}
    Returns: {enrichments: List[dict], total_iocs: int}
    """
    alert_id = params.get("alert_id")
    tenant_id = params.get("tenant_id")

    from psycopg2.extras import RealDictCursor
    from database.pool_manager import pooled_connection

    try:
        with pooled_connection("normal") as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute(
                    "SELECT source_ip, dest_ip, normalized_event FROM siem_alerts "
                    "WHERE id = %s AND tenant_id = %s",
                    (alert_id, tenant_id),
                )
                row = cur.fetchone()
                if not row:
                    return {"enrichments": [], "total_iocs": 0, "error": "Alert not found"}
    except Exception as e:
        logger.warning("enrich_alert_with_attack_surface DB error: %s", e)
        return {"enrichments": [], "total_iocs": 0, "error": "database_error"}

    # Extract IoCs
    iocs = []
    if row.get("source_ip"):
        iocs.append((str(row["source_ip"]), "ip"))
    if row.get("dest_ip"):
        iocs.append((str(row["dest_ip"]), "ip"))

    # Extract domains from normalized event
    norm = row.get("normalized_event", {})
    if isinstance(norm, dict):
        for field in ["hostname", "domain", "dest_domain"]:
            if norm.get(field):
                iocs.append((str(norm[field]), "domain"))

    recon = AttackSurfaceRecon()
    enrichments = []
    for ioc_value, ioc_type in iocs:
        result = await recon.enrich_ioc(ioc_value, ioc_type)
        enrichments.append(result)

    return {
        "enrichments": enrichments,
        "total_iocs": len(iocs),
    }
