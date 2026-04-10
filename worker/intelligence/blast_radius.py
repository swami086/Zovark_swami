"""Blast radius computation — SurrealDB graph traversal (Ticket 2)."""

from temporalio import activity


@activity.defn
async def compute_blast_radius(data: dict) -> dict:
    """Traverse entity graph in SurrealDB to compute blast radius for an investigation.

    Input: {investigation_id, tenant_id, time_window_hours: 72, max_hops: 2}
    Returns: {investigation_id, affected_entities, affected_investigations, total_entities, max_threat_score, summary}
    """
    from surreal_graph import blast_radius_surreal

    investigation_id = data.get("investigation_id")
    tenant_id = data.get("tenant_id")
    time_window_hours = data.get("time_window_hours", 72)
    max_hops = data.get("max_hops", 2)

    if not investigation_id or not tenant_id:
        return {
            "investigation_id": investigation_id,
            "affected_entities": [],
            "affected_investigations": [],
            "total_entities": 0,
            "max_threat_score": 0,
            "summary": "Missing parameters",
        }

    try:
        return await blast_radius_surreal(
            str(investigation_id), str(tenant_id), int(time_window_hours), int(max_hops)
        )
    except Exception as e:
        print(f"compute_blast_radius non-fatal error: {e}")
        return {
            "investigation_id": investigation_id,
            "affected_entities": [],
            "affected_investigations": [],
            "total_entities": 0,
            "max_threat_score": 0,
            "summary": f"Error: {e}",
        }
