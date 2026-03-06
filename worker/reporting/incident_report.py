"""Incident report generator — LLM-powered executive summary + timeline + remediation, with PDF output."""

import os
import io
import json
import time
import httpx
import psycopg2
from temporalio import activity

from security.prompt_sanitizer import wrap_untrusted_data


def _get_db():
    db_url = os.environ.get("DATABASE_URL", "postgresql://hydra:hydra_dev_2026@postgres:5432/hydra")
    return psycopg2.connect(db_url)


def _sync_commit(cur):
    cur.execute("SET LOCAL synchronous_commit = on")


def _generate_pdf(report_title, investigation_id, verdict, risk_score, exec_summary, timeline, remediation):
    """Generate PDF using reportlab. Returns bytes."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.lib.colors import HexColor

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

        story = []
        story.append(Paragraph("HYDRA Investigation Report", title_style))
        story.append(Paragraph(
            f"Investigation: {investigation_id}<br/>"
            f"Verdict: {verdict} | Risk Score: {risk_score}/100",
            meta_style
        ))
        story.append(Spacer(1, 12))

        story.append(Paragraph("Executive Summary", heading_style))
        # Escape XML-sensitive chars for reportlab
        safe_exec = (exec_summary or "N/A").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        for para in safe_exec.split("\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), body_style))

        story.append(Paragraph("Technical Timeline", heading_style))
        safe_timeline = (timeline or "N/A").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        for para in safe_timeline.split("\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), body_style))

        story.append(Paragraph("Remediation Steps", heading_style))
        safe_remediation = (remediation or "N/A").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        for para in safe_remediation.split("\n"):
            if para.strip():
                story.append(Paragraph(para.strip(), body_style))

        doc.build(story)
        return buf.getvalue()

    except ImportError:
        print("reportlab not installed, skipping PDF generation")
        return None
    except Exception as e:
        print(f"PDF generation failed (non-fatal): {e}")
        return None


@activity.defn
async def generate_incident_report(data: dict) -> dict:
    """Generate incident report with executive summary, timeline, remediation.

    Input: {investigation_id, tenant_id, summary, entities, edges, timeline,
            risk_score, verdict, attack_techniques, blast_radius}
    Returns: {report_id, markdown_length, pdf_size_bytes}
    """
    litellm_url = os.environ.get("LITELLM_URL", "http://litellm:4000/v1/chat/completions")
    api_key = os.environ.get("LITELLM_MASTER_KEY", "sk-hydra-dev-2026")
    llm_model = os.environ.get("HYDRA_LLM_MODEL", "fast")

    investigation_id = data.get("investigation_id")
    tenant_id = data.get("tenant_id")
    summary = data.get("summary", "")
    entities = data.get("entities", [])
    edges = data.get("edges", [])
    risk_score = data.get("risk_score", 0)
    verdict = data.get("verdict", "inconclusive")
    attack_techniques = data.get("attack_techniques", [])
    blast_radius = data.get("blast_radius", {})

    if not investigation_id or not tenant_id:
        return {"report_id": None, "markdown_length": 0, "pdf_size_bytes": 0, "error": "missing params"}

    # Build context for LLM
    entity_summary = ", ".join(
        f"{e.get('type', 'unknown')}:{e.get('value', '?')}" for e in entities[:20]
    ) if entities else "No entities extracted"

    blast_summary = blast_radius.get("summary", "Not computed") if blast_radius else "Not computed"

    context_text = (
        f"Investigation ID: {investigation_id}\n"
        f"Verdict: {verdict}\n"
        f"Risk Score: {risk_score}/100\n"
        f"MITRE Techniques: {', '.join(attack_techniques) if attack_techniques else 'None identified'}\n"
        f"Entities: {entity_summary}\n"
        f"Blast Radius: {blast_summary}\n"
        f"Investigation Output:\n{summary[:2000]}"
    )

    # Wrap investigation data as untrusted
    wrapped_context, safety_instruction = wrap_untrusted_data(context_text, "investigation")

    system_prompt = (
        "You are a security report writer for an MSSP. Generate a structured incident report. "
        "Output valid JSON with three keys: "
        "\"executive_summary\" (3-5 sentences for non-technical leadership, no jargon, no acronyms), "
        "\"technical_timeline\" (chronological attack chain with entity references and MITRE techniques), "
        "\"remediation_steps\" (specific actionable steps referencing actual entities like IPs, users, domains). "
        f"{safety_instruction}"
    )

    start_time = time.time()
    exec_summary = ""
    timeline_text = ""
    remediation_text = ""

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                litellm_url,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={
                    "model": llm_model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": wrapped_context},
                    ],
                    "temperature": 0.3,
                    "max_tokens": 2048,
                    "response_format": {"type": "json_object"},
                },
            )
            resp.raise_for_status()
            result = resp.json()
            content = result["choices"][0]["message"]["content"].strip()

            try:
                parsed = json.loads(content)
                exec_summary = parsed.get("executive_summary", content[:500])
                timeline_text = parsed.get("technical_timeline", "")
                remediation_text = parsed.get("remediation_steps", "")
                # Handle if remediation is a list
                if isinstance(remediation_text, list):
                    remediation_text = "\n".join(f"- {s}" for s in remediation_text)
                if isinstance(timeline_text, list):
                    timeline_text = "\n".join(f"- {s}" for s in timeline_text)
            except json.JSONDecodeError:
                exec_summary = content[:500]
                timeline_text = "Unable to parse structured timeline"
                remediation_text = "Unable to parse structured remediation"

    except Exception as e:
        print(f"Report LLM call failed: {e}")
        return {"report_id": None, "markdown_length": 0, "pdf_size_bytes": 0, "error": str(e)}

    # Build markdown report
    full_report = (
        f"# HYDRA Investigation Report\n\n"
        f"**Investigation ID:** {investigation_id}\n"
        f"**Verdict:** {verdict}\n"
        f"**Risk Score:** {risk_score}/100\n\n"
        f"---\n\n"
        f"## Executive Summary\n\n{exec_summary}\n\n"
        f"## Technical Timeline\n\n{timeline_text}\n\n"
        f"## Remediation Steps\n\n{remediation_text}\n"
    )

    # Generate PDF
    pdf_data = _generate_pdf(
        "HYDRA Investigation Report", investigation_id,
        verdict, risk_score, exec_summary, timeline_text, remediation_text
    )

    # Store in DB
    report_id = None
    conn = _get_db()
    try:
        with conn.cursor() as cur:
            _sync_commit(cur)
            # Store markdown report
            cur.execute("""
                INSERT INTO investigation_reports
                (investigation_id, tenant_id, report_format, executive_summary,
                 technical_timeline, remediation_steps, full_report, generated_by)
                VALUES (%s, %s, 'markdown', %s, %s, %s, %s, %s)
                RETURNING id
            """, (investigation_id, tenant_id, exec_summary, timeline_text,
                  remediation_text, full_report, llm_model))
            row = cur.fetchone()
            report_id = str(row[0]) if row else None

            # Store PDF if generated
            if pdf_data:
                cur.execute("""
                    INSERT INTO investigation_reports
                    (investigation_id, tenant_id, report_format, executive_summary,
                     technical_timeline, remediation_steps, pdf_data, generated_by)
                    VALUES (%s, %s, 'pdf', %s, %s, %s, %s, %s)
                """, (investigation_id, tenant_id, exec_summary, timeline_text,
                      remediation_text, pdf_data, llm_model))

        conn.commit()
    except Exception as e:
        print(f"Report DB insert failed (non-fatal): {e}")
    finally:
        conn.close()

    execution_ms = int((time.time() - start_time) * 1000)
    print(f"Generated report for {investigation_id}: md={len(full_report)} chars, pdf={len(pdf_data) if pdf_data else 0} bytes, {execution_ms}ms")

    return {
        "report_id": report_id,
        "markdown_length": len(full_report),
        "pdf_size_bytes": len(pdf_data) if pdf_data else 0,
    }
