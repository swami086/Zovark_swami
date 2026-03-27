"""
ZOVARC Email Integration — Temporal Activity
Sends HTML email notifications for investigation events.
Supports SMTP with TLS, multiple recipients per tenant.
"""
import os
import ssl
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from temporalio import activity


SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("SMTP_FROM", "zovarc@zovarc.local")
SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes")


# ─── HTML TEMPLATES ─────────────────────────────────────

INVESTIGATION_DIGEST_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
.container {{ max-width: 600px; margin: 0 auto; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
.header {{ background: {header_color}; color: white; padding: 20px 24px; }}
.header h1 {{ margin: 0; font-size: 20px; }}
.body {{ padding: 24px; }}
.field {{ margin-bottom: 12px; }}
.field-label {{ font-weight: 600; color: #374151; font-size: 13px; text-transform: uppercase; }}
.field-value {{ color: #111827; margin-top: 4px; }}
.badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }}
.severity-critical {{ background: #fecaca; color: #991b1b; }}
.severity-high {{ background: #fed7aa; color: #9a3412; }}
.severity-medium {{ background: #fef08a; color: #854d0e; }}
.severity-low {{ background: #bbf7d0; color: #166534; }}
.footer {{ padding: 16px 24px; background: #f9fafb; color: #6b7280; font-size: 12px; border-top: 1px solid #e5e7eb; }}
table {{ width: 100%; border-collapse: collapse; }}
td {{ padding: 8px 12px; border-bottom: 1px solid #e5e7eb; }}
</style></head>
<body>
<div class="container">
  <div class="header"><h1>{title}</h1></div>
  <div class="body">
    <table>
      <tr><td class="field-label">Investigation ID</td><td>{investigation_id}</td></tr>
      <tr><td class="field-label">Severity</td><td><span class="badge severity-{severity}">{severity_upper}</span></td></tr>
      <tr><td class="field-label">Verdict</td><td>{verdict}</td></tr>
      <tr><td class="field-label">Entities</td><td>{entities}</td></tr>
      <tr><td class="field-label">MITRE Techniques</td><td>{mitre}</td></tr>
    </table>
    <div class="field" style="margin-top: 16px;">
      <div class="field-label">Summary</div>
      <div class="field-value">{summary}</div>
    </div>
  </div>
  <div class="footer">Sent by ZOVARC SOC Automation Platform</div>
</div>
</body>
</html>
"""

APPROVAL_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
.container {{ max-width: 600px; margin: 0 auto; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
.header {{ background: #ea580c; color: white; padding: 20px 24px; }}
.header h1 {{ margin: 0; font-size: 20px; }}
.body {{ padding: 24px; }}
.field {{ margin-bottom: 12px; }}
.field-label {{ font-weight: 600; color: #374151; font-size: 13px; }}
.field-value {{ color: #111827; margin-top: 4px; }}
.footer {{ padding: 16px 24px; background: #f9fafb; color: #6b7280; font-size: 12px; border-top: 1px solid #e5e7eb; }}
</style></head>
<body>
<div class="container">
  <div class="header"><h1>Approval Required</h1></div>
  <div class="body">
    <div class="field"><div class="field-label">Action</div><div class="field-value">{action}</div></div>
    <div class="field"><div class="field-label">Investigation</div><div class="field-value">{investigation_id}</div></div>
    <div class="field"><div class="field-label">Requester</div><div class="field-value">{requester}</div></div>
    <div class="field"><div class="field-label">Reason</div><div class="field-value">{reason}</div></div>
    <p>Please log in to the ZOVARC dashboard to approve or deny this action.</p>
  </div>
  <div class="footer">Sent by ZOVARC SOC Automation Platform</div>
</div>
</body>
</html>
"""

SLA_BREACH_TEMPLATE = """
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><style>
body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }}
.container {{ max-width: 600px; margin: 0 auto; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
.header {{ background: #dc2626; color: white; padding: 20px 24px; }}
.header h1 {{ margin: 0; font-size: 20px; }}
.body {{ padding: 24px; }}
.field {{ margin-bottom: 12px; }}
.field-label {{ font-weight: 600; color: #374151; font-size: 13px; }}
.field-value {{ color: #111827; margin-top: 4px; font-size: 18px; font-weight: 600; }}
.footer {{ padding: 16px 24px; background: #f9fafb; color: #6b7280; font-size: 12px; border-top: 1px solid #e5e7eb; }}
</style></head>
<body>
<div class="container">
  <div class="header"><h1>SLA Breach Alert</h1></div>
  <div class="body">
    <div class="field"><div class="field-label">Investigation</div><div class="field-value">{investigation_id}</div></div>
    <div class="field"><div class="field-label">Severity</div><div class="field-value">{severity}</div></div>
    <div class="field"><div class="field-label">SLA Target</div><div class="field-value">{sla_target} minutes</div></div>
    <div class="field"><div class="field-label">Elapsed</div><div class="field-value">{elapsed} minutes</div></div>
    <p>This investigation has exceeded its SLA target. Immediate attention required.</p>
  </div>
  <div class="footer">Sent by ZOVARC SOC Automation Platform</div>
</div>
</body>
</html>
"""

SEVERITY_HEADER_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
    "info": "#2563eb",
}


def _render_investigation_digest(data: dict) -> tuple:
    """Returns (subject, html_body)."""
    severity = data.get("severity", "medium").lower()
    investigation_id = data.get("investigation_id", "N/A")
    verdict = data.get("verdict", "unknown")
    entities = data.get("entities", [])
    mitre = data.get("mitre_techniques", [])

    subject = f"[ZOVARC] Investigation {verdict.upper()} — {investigation_id[:8]}"
    html = INVESTIGATION_DIGEST_TEMPLATE.format(
        title=data.get("title", f"Investigation Complete: {verdict}"),
        header_color=SEVERITY_HEADER_COLORS.get(severity, "#6b7280"),
        investigation_id=investigation_id,
        severity=severity,
        severity_upper=severity.upper(),
        verdict=verdict.upper(),
        entities=", ".join(entities[:10]) if entities else "None",
        mitre=", ".join(mitre[:5]) if mitre else "None",
        summary=data.get("summary", "No summary available.")[:1000],
    )
    return subject, html


def _render_approval(data: dict) -> tuple:
    subject = f"[ZOVARC] Approval Required — {data.get('action', 'unknown')}"
    html = APPROVAL_TEMPLATE.format(
        action=data.get("action", "unknown"),
        investigation_id=data.get("investigation_id", "N/A"),
        requester=data.get("requester", "system"),
        reason=data.get("reason", "Manual approval required"),
    )
    return subject, html


def _render_sla_breach(data: dict) -> tuple:
    subject = f"[ZOVARC] SLA Breach — Investigation {data.get('investigation_id', 'N/A')[:8]}"
    html = SLA_BREACH_TEMPLATE.format(
        investigation_id=data.get("investigation_id", "N/A"),
        severity=data.get("severity", "high").upper(),
        sla_target=data.get("sla_target_minutes", 0),
        elapsed=data.get("elapsed_minutes", 0),
    )
    return subject, html


RENDERERS = {
    "investigation_complete": _render_investigation_digest,
    "investigation_digest": _render_investigation_digest,
    "approval_needed": _render_approval,
    "approval_alert": _render_approval,
    "sla_breach": _render_sla_breach,
}


@activity.defn
async def send_email_notification(data: dict) -> dict:
    """
    Send an HTML email notification.

    Args:
        data: {
            "event_type": "investigation_complete"|"approval_needed"|"sla_breach",
            "recipients": list[str],  # email addresses
            "smtp_host": optional override,
            ...event-specific fields
        }

    Returns:
        {"status": "sent"|"skipped"|"error", "recipients": int}
    """
    event_type = data.get("event_type", "investigation_complete")
    recipients = data.get("recipients", [])
    smtp_host = data.get("smtp_host") or SMTP_HOST

    if not smtp_host:
        activity.logger.warning("SMTP not configured — skipping email")
        return {"status": "skipped", "event_type": event_type, "reason": "smtp_not_configured"}

    if not recipients:
        return {"status": "skipped", "event_type": event_type, "reason": "no_recipients"}

    renderer = RENDERERS.get(event_type)
    if not renderer:
        return {"status": "error", "event_type": event_type, "reason": f"unknown event type: {event_type}"}

    subject, html_body = renderer(data)

    smtp_port = int(data.get("smtp_port") or SMTP_PORT)
    smtp_user = data.get("smtp_user") or SMTP_USER
    smtp_password = data.get("smtp_password") or SMTP_PASSWORD
    from_addr = data.get("from_address") or SMTP_FROM
    use_tls = SMTP_USE_TLS

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(recipients)
        msg.attach(MIMEText(html_body, "html"))

        if use_tls:
            context = ssl.create_default_context()
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
            server.ehlo()
            server.starttls(context=context)
        else:
            server = smtplib.SMTP(smtp_host, smtp_port, timeout=15)

        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)

        server.sendmail(from_addr, recipients, msg.as_string())
        server.quit()

        activity.logger.info("Email sent", event_type=event_type, recipients=len(recipients))
        return {"status": "sent", "event_type": event_type, "recipients": len(recipients)}

    except Exception as e:
        activity.logger.error("Email send error", error=str(e))
        return {"status": "error", "event_type": event_type, "error": str(e)}
