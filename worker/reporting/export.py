"""Investigation report export — JSON, Markdown, and PDF formats.

Exports investigation data to multiple formats and stores in MinIO (S3-compatible)
object storage. Follows existing patterns from incident_report.py.

Activity: export_investigation_report
"""

import os
import io
import json
import time
from datetime import datetime, timezone
from temporalio import activity


def _get_db():
    import psycopg2
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)


def _sync_commit(cur):
    cur.execute("SET LOCAL synchronous_commit = on")


def _get_minio_client():
    """Get MinIO client for S3-compatible storage."""
    try:
        from minio import Minio
        endpoint = os.environ.get("MINIO_ENDPOINT", "minio:9000")
        access_key = os.environ.get("MINIO_ROOT_USER", "hydra")
        secret_key = os.environ.get("MINIO_ROOT_PASSWORD", "hydra_dev_2026")
        secure = os.environ.get("MINIO_SECURE", "false").lower() == "true"
        return Minio(endpoint, access_key=access_key, secret_key=secret_key, secure=secure)
    except ImportError:
        return None


def _ensure_bucket(client, bucket_name="hydra-reports"):
    """Ensure the reports bucket exists."""
    if client and not client.bucket_exists(bucket_name):
        client.make_bucket(bucket_name)


def _export_json(data: dict) -> str:
    """Export investigation data as formatted JSON."""
    export_data = {
        "export_format": "json",
        "export_version": "1.0",
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "investigation": {
            "id": data.get("investigation_id"),
            "tenant_id": data.get("tenant_id"),
            "verdict": data.get("verdict", "inconclusive"),
            "risk_score": data.get("risk_score", 0),
            "summary": data.get("summary", ""),
            "status": data.get("status", "completed"),
        },
        "entities": data.get("entities", []),
        "edges": data.get("edges", []),
        "timeline": data.get("timeline", []),
        "attack_techniques": data.get("attack_techniques", []),
        "blast_radius": data.get("blast_radius", {}),
        "steps": data.get("steps", []),
        "metadata": {
            "total_entities": len(data.get("entities", [])),
            "total_edges": len(data.get("edges", [])),
            "total_steps": len(data.get("steps", [])),
            "execution_ms": data.get("execution_ms"),
            "model_used": data.get("model_used"),
        },
    }
    return json.dumps(export_data, indent=2, default=str)


def _export_markdown(data: dict) -> str:
    """Export investigation data as formatted Markdown."""
    investigation_id = data.get("investigation_id", "unknown")
    verdict = data.get("verdict", "inconclusive")
    risk_score = data.get("risk_score", 0)
    summary = data.get("summary", "No summary available.")
    entities = data.get("entities", [])
    attack_techniques = data.get("attack_techniques", [])
    blast_radius = data.get("blast_radius", {})
    steps = data.get("steps", [])
    timeline = data.get("timeline", [])

    lines = [
        f"# HYDRA Investigation Report",
        "",
        f"**Investigation ID:** `{investigation_id}`",
        f"**Verdict:** {verdict}",
        f"**Risk Score:** {risk_score}/100",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        summary,
        "",
    ]

    # MITRE techniques
    if attack_techniques:
        lines.append("## MITRE ATT&CK Techniques")
        lines.append("")
        for tech in attack_techniques:
            lines.append(f"- {tech}")
        lines.append("")

    # Entities
    if entities:
        lines.append("## Entities")
        lines.append("")
        lines.append("| Type | Value | Role |")
        lines.append("|------|-------|------|")
        for entity in entities[:50]:  # Cap at 50 for readability
            etype = entity.get("type", "unknown")
            evalue = entity.get("value", "?")
            erole = entity.get("role", "-")
            lines.append(f"| {etype} | `{evalue}` | {erole} |")
        if len(entities) > 50:
            lines.append(f"| ... | +{len(entities) - 50} more | |")
        lines.append("")

    # Blast radius
    if blast_radius:
        lines.append("## Blast Radius")
        lines.append("")
        blast_summary = blast_radius.get("summary", "Not computed")
        lines.append(blast_summary)
        affected = blast_radius.get("affected_assets", [])
        if affected:
            lines.append("")
            lines.append("**Affected Assets:**")
            for asset in affected[:20]:
                lines.append(f"- {asset}")
        lines.append("")

    # Investigation steps
    if steps:
        lines.append("## Investigation Steps")
        lines.append("")
        for step in steps:
            step_num = step.get("step_number", "?")
            step_type = step.get("step_type", "unknown")
            step_status = step.get("status", "unknown")
            step_ms = step.get("execution_ms", "?")
            lines.append(f"### Step {step_num}: {step_type}")
            lines.append(f"**Status:** {step_status} | **Duration:** {step_ms}ms")
            if step.get("prompt"):
                lines.append(f"\n> {step['prompt']}")
            if step.get("output"):
                lines.append(f"\n```\n{str(step['output'])[:500]}\n```")
            lines.append("")

    # Timeline
    if timeline:
        lines.append("## Timeline")
        lines.append("")
        for event in timeline:
            ts = event.get("timestamp", "?")
            desc = event.get("description", "")
            lines.append(f"- **{ts}** — {desc}")
        lines.append("")

    lines.extend([
        "---",
        "",
        "*Generated by HYDRA SOC Automation Platform*",
    ])

    return "\n".join(lines)


def _export_pdf(data: dict) -> bytes:
    """Export investigation data as PDF.

    Requires reportlab. Returns None if not available.
    """
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor, black, grey

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=0.75 * inch, bottomMargin=0.75 * inch)
        styles = getSampleStyleSheet()

        title_style = ParagraphStyle(
            'ReportTitle', parent=styles['Title'],
            fontSize=18, textColor=HexColor('#1a1a2e'),
            spaceAfter=6,
        )
        heading_style = ParagraphStyle(
            'SectionHeading', parent=styles['Heading2'],
            fontSize=14, textColor=HexColor('#16213e'),
            spaceBefore=16, spaceAfter=8,
        )
        body_style = ParagraphStyle(
            'ReportBody', parent=styles['Normal'],
            fontSize=10, leading=14, spaceAfter=6,
        )
        meta_style = ParagraphStyle(
            'Meta', parent=styles['Normal'],
            fontSize=9, textColor=HexColor('#666666'),
            spaceAfter=12,
        )

        def _escape(text):
            return str(text or "N/A").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

        story = []

        # Title
        story.append(Paragraph("HYDRA Investigation Report", title_style))
        investigation_id = data.get("investigation_id", "unknown")
        verdict = data.get("verdict", "inconclusive")
        risk_score = data.get("risk_score", 0)
        story.append(Paragraph(
            f"Investigation: {_escape(investigation_id)}<br/>"
            f"Verdict: {_escape(verdict)} | Risk Score: {risk_score}/100<br/>"
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            meta_style,
        ))
        story.append(Spacer(1, 12))

        # Summary
        story.append(Paragraph("Executive Summary", heading_style))
        summary = _escape(data.get("summary", "No summary available."))
        for para in summary.split("\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), body_style))
        story.append(Spacer(1, 8))

        # Entities table
        entities = data.get("entities", [])
        if entities:
            story.append(Paragraph("Entities", heading_style))
            table_data = [["Type", "Value", "Role"]]
            for e in entities[:30]:
                table_data.append([
                    _escape(e.get("type", "")),
                    _escape(e.get("value", "")),
                    _escape(e.get("role", "-")),
                ])
            t = Table(table_data, colWidths=[1.5 * inch, 3 * inch, 1.5 * inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), HexColor('#16213e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), HexColor('#ffffff')),
                ('FONTSIZE', (0, 0), (-1, -1), 8),
                ('GRID', (0, 0), (-1, -1), 0.5, grey),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ]))
            story.append(t)

        # Techniques
        techniques = data.get("attack_techniques", [])
        if techniques:
            story.append(Paragraph("MITRE ATT&CK Techniques", heading_style))
            for tech in techniques:
                story.append(Paragraph(f"- {_escape(tech)}", body_style))

        doc.build(story)
        return buf.getvalue()

    except ImportError:
        print("reportlab not installed — PDF export skipped")
        return None
    except Exception as e:
        print(f"PDF generation failed (non-fatal): {e}")
        return None


def _store_in_minio(minio_client, bucket, key, data_bytes, content_type):
    """Upload bytes to MinIO."""
    if minio_client is None:
        return False
    try:
        _ensure_bucket(minio_client, bucket)
        stream = io.BytesIO(data_bytes)
        minio_client.put_object(
            bucket_name=bucket,
            object_name=key,
            data=stream,
            length=len(data_bytes),
            content_type=content_type,
        )
        return True
    except Exception as e:
        print(f"MinIO upload failed (non-fatal): {e}")
        return False


@activity.defn
async def export_investigation_report(data: dict) -> dict:
    """Export investigation report in multiple formats.

    Input: {
        investigation_id, tenant_id, summary, entities, edges,
        timeline, risk_score, verdict, attack_techniques, blast_radius,
        steps, formats (list of "json", "markdown", "pdf")
    }

    Returns: {
        investigation_id, formats_exported, json_size, markdown_size,
        pdf_size, minio_keys, export_ms
    }
    """
    start_time = time.time()

    investigation_id = data.get("investigation_id")
    tenant_id = data.get("tenant_id")
    formats = data.get("formats", ["json", "markdown", "pdf"])

    if not investigation_id or not tenant_id:
        return {
            "investigation_id": investigation_id,
            "formats_exported": [],
            "error": "missing investigation_id or tenant_id",
        }

    minio_client = _get_minio_client()
    bucket = "hydra-reports"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_key = f"{tenant_id}/{investigation_id}/{timestamp}"

    results = {
        "investigation_id": investigation_id,
        "formats_exported": [],
        "json_size": 0,
        "markdown_size": 0,
        "pdf_size": 0,
        "minio_keys": [],
    }

    # JSON export
    if "json" in formats:
        json_content = _export_json(data)
        json_bytes = json_content.encode("utf-8")
        results["json_size"] = len(json_bytes)
        results["formats_exported"].append("json")

        key = f"{base_key}/report.json"
        if _store_in_minio(minio_client, bucket, key, json_bytes, "application/json"):
            results["minio_keys"].append(key)

    # Markdown export
    if "markdown" in formats:
        md_content = _export_markdown(data)
        md_bytes = md_content.encode("utf-8")
        results["markdown_size"] = len(md_bytes)
        results["formats_exported"].append("markdown")

        key = f"{base_key}/report.md"
        if _store_in_minio(minio_client, bucket, key, md_bytes, "text/markdown"):
            results["minio_keys"].append(key)

    # PDF export
    if "pdf" in formats:
        pdf_bytes = _export_pdf(data)
        if pdf_bytes:
            results["pdf_size"] = len(pdf_bytes)
            results["formats_exported"].append("pdf")

            key = f"{base_key}/report.pdf"
            if _store_in_minio(minio_client, bucket, key, pdf_bytes, "application/pdf"):
                results["minio_keys"].append(key)
        else:
            # PDF generation not available (reportlab not installed)
            results["formats_exported"].append("pdf_skipped")

    # Store metadata in DB
    export_ms = int((time.time() - start_time) * 1000)
    results["export_ms"] = export_ms

    try:
        conn = _get_db()
        with conn.cursor() as cur:
            _sync_commit(cur)
            cur.execute("""
                INSERT INTO agent_audit_log (tenant_id, action, resource_type, resource_id, details)
                VALUES (%s, %s, %s, %s, %s)
            """, (
                tenant_id,
                "report_exported",
                "task",
                investigation_id,
                json.dumps({
                    "formats": results["formats_exported"],
                    "json_size": results["json_size"],
                    "markdown_size": results["markdown_size"],
                    "pdf_size": results["pdf_size"],
                    "export_ms": export_ms,
                }),
            ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Export audit log failed (non-fatal): {e}")

    print(
        f"Exported report for {investigation_id}: "
        f"formats={results['formats_exported']}, "
        f"json={results['json_size']}B, md={results['markdown_size']}B, "
        f"pdf={results['pdf_size']}B, {export_ms}ms"
    )

    return results
