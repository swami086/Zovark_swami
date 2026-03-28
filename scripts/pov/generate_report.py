#!/usr/bin/env python3
"""Generate side-by-side PoV comparison report.

Reads completed investigations from DB and generates:
1. Summary statistics (total alerts, investigated, avg time, accuracy)
2. Per-severity breakdown with risk scores
3. MTTR calculation: avg investigation time
4. Entity extraction quality: unique IOCs found
5. Risk score distribution
6. Detection rule generation: Sigma rules created
7. ROI calculation: analyst hours saved

Output: Markdown report (default) or HTML dashboard

Usage:
  python generate_report.py --tenant-id <uuid> --output report.md
  python generate_report.py --tenant-id <uuid> --output report.html --format html
"""
import argparse
import os
import sys
from datetime import datetime

import psycopg2
from psycopg2.extras import RealDictCursor


def get_db():
    url = os.environ.get("DATABASE_URL", "postgresql://zovark:zovark_dev_2026@localhost:5432/zovark")
    return psycopg2.connect(url)


def gather_stats(tenant_id: str) -> dict:
    """Gather all statistics for the PoV report."""
    conn = get_db()
    stats = {}

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Investigation summary
            cur.execute("""
                SELECT
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) AS completed,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) AS failed,
                    ROUND(AVG(execution_ms)::numeric / 1000, 1) AS avg_seconds,
                    ROUND(AVG(CASE WHEN status = 'completed' THEN execution_ms END)::numeric / 1000, 1) AS avg_completed_seconds,
                    COALESCE(SUM(tokens_used_input), 0) AS total_input_tokens,
                    COALESCE(SUM(tokens_used_output), 0) AS total_output_tokens
                FROM agent_tasks WHERE tenant_id = %s
            """, (tenant_id,))
            stats['investigations'] = dict(cur.fetchone())

            # Per-severity breakdown
            cur.execute("""
                SELECT
                    COALESCE(severity, input->>'severity', 'unknown') AS severity,
                    COUNT(*) AS count,
                    ROUND(AVG(execution_ms)::numeric / 1000, 1) AS avg_seconds
                FROM agent_tasks WHERE tenant_id = %s AND status = 'completed'
                GROUP BY severity ORDER BY count DESC
            """, (tenant_id,))
            stats['severity_breakdown'] = [dict(r) for r in cur.fetchall()]

            # Entity extraction stats
            cur.execute("""
                SELECT
                    COUNT(DISTINCT eo.entity_id) AS unique_entities,
                    COUNT(DISTINCT eo.investigation_id) AS investigations_with_entities
                FROM entity_observations eo
                JOIN investigations i ON i.id = eo.investigation_id
                WHERE i.tenant_id = %s
            """, (tenant_id,))
            stats['entities'] = dict(cur.fetchone())

            # Entity type distribution
            cur.execute("""
                SELECT e.entity_type, COUNT(*) AS count
                FROM entity_observations eo
                JOIN entities e ON e.id = eo.entity_id
                JOIN investigations i ON i.id = eo.investigation_id
                WHERE i.tenant_id = %s
                GROUP BY e.entity_type ORDER BY count DESC LIMIT 10
            """, (tenant_id,))
            stats['entity_types'] = [dict(r) for r in cur.fetchall()]

            # Sigma rules generated
            cur.execute("""
                SELECT COUNT(*) AS total,
                       SUM(CASE WHEN status = 'validating' THEN 1 ELSE 0 END) AS valid
                FROM detection_candidates WHERE tenant_id = %s
            """, (tenant_id,))
            stats['sigma_rules'] = dict(cur.fetchone())

            # Feedback stats (if any)
            cur.execute("""
                SELECT
                    COUNT(*) AS total,
                    ROUND(AVG(CASE WHEN verdict_correct THEN 1.0 ELSE 0.0 END)::numeric, 3) AS accuracy,
                    SUM(CASE WHEN false_positive THEN 1 ELSE 0 END) AS false_positives,
                    SUM(CASE WHEN missed_threat THEN 1 ELSE 0 END) AS missed_threats
                FROM investigation_feedback WHERE tenant_id = %s
            """, (tenant_id,))
            stats['feedback'] = dict(cur.fetchone())

    finally:
        conn.close()

    return stats


def generate_markdown(stats: dict, tenant_id: str) -> str:
    """Generate Markdown report."""
    inv = stats['investigations']
    ent = stats['entities']
    sig = stats['sigma_rules']
    fb = stats['feedback']

    total = int(inv['total'] or 0)
    completed = int(inv['completed'] or 0)
    avg_sec = float(inv['avg_completed_seconds'] or 0)

    # ROI calculation
    analyst_hourly = 75  # USD
    manual_minutes = 45  # Average manual investigation time
    zovark_minutes = avg_sec / 60 if avg_sec else 0.5
    hours_saved_per_inv = (manual_minutes - zovark_minutes) / 60
    total_hours_saved = hours_saved_per_inv * completed
    annual_projection = total_hours_saved * (250 / max(1, total)) * 365 if total > 0 else 0

    report = f"""# ZOVARK 48-Hour Proof of Value Report

**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}
**Tenant:** {tenant_id}

## Executive Summary

| Metric | Value |
|--------|-------|
| Alerts processed | {total} |
| Investigations completed | {completed} |
| Average investigation time | {avg_sec:.1f} seconds |
| Unique IOCs extracted | {int(ent.get('unique_entities', 0))} |
| Sigma rules generated | {int(sig.get('total', 0))} (valid: {int(sig.get('valid', 0))}) |
| Estimated analyst hours saved | {total_hours_saved:.1f} |

## Alert Triage

| Severity | Count | Avg Time (s) |
|----------|-------|---------------|
"""

    for sev in stats['severity_breakdown']:
        report += f"| {sev['severity']} | {sev['count']} | {float(sev['avg_seconds'] or 0):.1f} |\n"

    report += f"""
## Entity Extraction Quality

- Unique entities found: {int(ent.get('unique_entities', 0))}
- Investigations with entities: {int(ent.get('investigations_with_entities', 0))}

| Entity Type | Count |
|-------------|-------|
"""
    for et in stats['entity_types']:
        report += f"| {et['entity_type']} | {et['count']} |\n"

    report += f"""
## MTTR Comparison

| Metric | Zovark | Manual (Industry Avg) | Improvement |
|--------|-------|----------------------|-------------|
| Time to triage | {avg_sec:.0f} sec | 15 min | {(900/max(avg_sec,1)):.0f}x faster |
| Time to investigate | {avg_sec:.0f} sec | 45 min | {(2700/max(avg_sec,1)):.0f}x faster |
| Time to report | instant | 30 min | automated |

## ROI Calculation

- Analyst hourly cost: ${analyst_hourly}
- Manual investigation time: {manual_minutes} min avg
- Zovark investigation time: {zovark_minutes:.1f} min avg
- Hours saved per investigation: {hours_saved_per_inv:.2f}
- **Total hours saved (this PoV): {total_hours_saved:.1f}**
- **Projected annual savings: ${annual_projection * analyst_hourly:,.0f}**
"""

    if int(fb.get('total', 0)) > 0:
        report += f"""
## Analyst Feedback

| Metric | Value |
|--------|-------|
| Total feedback | {int(fb['total'])} |
| Accuracy | {float(fb['accuracy'] or 0) * 100:.1f}% |
| False positives | {int(fb['false_positives'] or 0)} |
| Missed threats | {int(fb['missed_threats'] or 0)} |
"""

    report += f"""
## Detection Rules

- Candidates generated: {int(sig.get('total', 0))}
- Valid Sigma rules: {int(sig.get('valid', 0))}

---

*Report generated by ZOVARK PoV package v0.17.0*
"""
    return report


def generate_html(stats: dict, tenant_id: str) -> str:
    """Generate single-file HTML dashboard."""
    md = generate_markdown(stats, tenant_id)
    # Wrap markdown in basic HTML with styling
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZOVARK PoV Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1a1a2e; background: #f8f9fa; }}
  h1 {{ color: #16213e; border-bottom: 3px solid #0f3460; padding-bottom: 10px; }}
  h2 {{ color: #0f3460; margin-top: 2em; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
  th, td {{ border: 1px solid #dee2e6; padding: 8px 12px; text-align: left; }}
  th {{ background: #0f3460; color: white; }}
  tr:nth-child(even) {{ background: #e8ecf1; }}
  code {{ background: #e8ecf1; padding: 2px 6px; border-radius: 3px; }}
  pre {{ background: #1a1a2e; color: #e8ecf1; padding: 16px; border-radius: 8px; overflow-x: auto; }}
</style>
</head>
<body>
<pre>{md}</pre>
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser(description="Generate ZOVARK PoV comparison report")
    parser.add_argument("--tenant-id", required=True, help="Tenant UUID")
    parser.add_argument("--output", default="report.md", help="Output file path")
    parser.add_argument("--format", choices=["md", "html"], default="md",
                        help="Output format (default: md)")
    args = parser.parse_args()

    # Auto-detect format from extension
    if args.output.endswith('.html'):
        args.format = 'html'

    print(f"Gathering statistics for tenant {args.tenant_id}...")
    stats = gather_stats(args.tenant_id)

    print(f"Generating {args.format} report...")
    if args.format == 'html':
        content = generate_html(stats, args.tenant_id)
    else:
        content = generate_markdown(stats, args.tenant_id)

    with open(args.output, 'w') as f:
        f.write(content)

    print(f"Report written to {args.output}")
    inv = stats['investigations']
    print(f"  {int(inv['total'] or 0)} investigations, {int(inv['completed'] or 0)} completed")


if __name__ == "__main__":
    main()
