#!/usr/bin/env python3
"""
Telemetry Reader — runs at the start of every AutoResearch cycle.
Queries ALL live data sources and produces a priority queue of issues.
Output: autoresearch/continuous/cycle_N_telemetry.json
"""
import json, os, sys, time, subprocess
from datetime import datetime, timedelta

try:
    import httpx
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "httpx", "-q"])
    import httpx

try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

CYCLE = int(sys.argv[1]) if len(sys.argv) > 1 else 0
OUTPUT_DIR = "autoresearch/continuous"
os.makedirs(OUTPUT_DIR, exist_ok=True)

report = {
    "cycle": CYCLE,
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "sources": {},
    "issues": [],          # populated below — each issue has severity, category, detail
    "priority_queue": [],  # top issues ranked by impact
}

# ─────────────────────────────────────────────────────────────────
# SOURCE 1: SIGNOZ — Trace Analysis
# Query ClickHouse directly for span-level performance data
# ─────────────────────────────────────────────────────────────────
print("Reading Signoz traces...")
try:
    # ClickHouse HTTP interface (from host perspective)
    CH_URL = "http://localhost:8123"
    # Try container name if localhost fails
    CH_URL_FALLBACK = "http://zovark-clickhouse:8123"

    def ch_query(sql):
        resp = httpx.post(CH_URL, content=sql,
                          params={"database": "signoz_traces"},
                          timeout=30)
        if resp.status_code == 200:
            lines = resp.text.strip().split("\n")
            return [line.split("\t") for line in lines if line]
        return []

    # 1a. Slowest spans in last 6 hours
    slow_spans = ch_query("""
        SELECT
            name,
            quantile(0.95)(durationNano) / 1e9 AS p95_seconds,
            quantile(0.50)(durationNano) / 1e9 AS p50_seconds,
            count() AS call_count,
            countIf(statusCode = 2) AS error_count
        FROM signoz_index_v2
        WHERE timestamp > now() - INTERVAL 6 HOUR
        AND name NOT LIKE '%health%'
        GROUP BY name
        ORDER BY p95_seconds DESC
        LIMIT 20
    """)

    # 1b. Error rate by service
    error_rates = ch_query("""
        SELECT
            serviceName,
            count() AS total,
            countIf(statusCode = 2) AS errors,
            round(countIf(statusCode = 2) * 100.0 / count(), 2) AS error_pct
        FROM signoz_index_v2
        WHERE timestamp > now() - INTERVAL 6 HOUR
        GROUP BY serviceName
        ORDER BY error_pct DESC
    """)

    # 1c. LLM call latency trend (is it getting worse?)
    llm_trend = ch_query("""
        SELECT
            toStartOfHour(timestamp) AS hour,
            avg(durationNano) / 1e9 AS avg_seconds,
            quantile(0.95)(durationNano) / 1e9 AS p95_seconds,
            count() AS calls
        FROM signoz_index_v2
        WHERE name = 'llm.call'
        AND timestamp > now() - INTERVAL 24 HOUR
        GROUP BY hour
        ORDER BY hour DESC
        LIMIT 24
    """)

    # 1d. Tool-level error traces
    tool_errors = ch_query("""
        SELECT
            name,
            count() AS error_count,
            any(traceID) AS example_trace_id
        FROM signoz_index_v2
        WHERE statusCode = 2
        AND name LIKE 'tool.%'
        AND timestamp > now() - INTERVAL 6 HOUR
        GROUP BY name
        ORDER BY error_count DESC
        LIMIT 10
    """)

    # 1e. Investigation path distribution (Path A vs C)
    path_dist = ch_query("""
        SELECT
            tagMap['execution_mode'] AS path,
            count() AS count
        FROM signoz_index_v2
        WHERE name = 'investigation.complete'
        AND timestamp > now() - INTERVAL 6 HOUR
        GROUP BY path
    """)

    # 1f. Slowest individual tool calls (find outliers)
    tool_outliers = ch_query("""
        SELECT
            name,
            traceID,
            durationNano / 1e6 AS duration_ms,
            tagMap['tenant_id'] AS tenant,
            tagMap['task_type'] AS task_type
        FROM signoz_index_v2
        WHERE name LIKE 'tool.%'
        AND durationNano > 1e9
        AND timestamp > now() - INTERVAL 6 HOUR
        ORDER BY durationNano DESC
        LIMIT 20
    """)

    report["sources"]["signoz"] = {
        "status": "ok",
        "slow_spans": slow_spans[:10],
        "error_rates": error_rates,
        "llm_trend": llm_trend[:6],
        "tool_errors": tool_errors,
        "path_distribution": path_dist,
        "tool_outliers": tool_outliers[:10],
    }

    # Generate issues from Signoz data
    for row in slow_spans:
        if len(row) >= 2:
            name, p95 = row[0], float(row[1]) if row[1] != '\\N' else 0
            if p95 > 30:
                report["issues"].append({
                    "severity": "HIGH",
                    "source": "signoz",
                    "category": "latency",
                    "detail": f"Span '{name}' p95={p95:.1f}s — investigate and optimize",
                    "span_name": name,
                    "p95_seconds": p95,
                })
            elif p95 > 10:
                report["issues"].append({
                    "severity": "MEDIUM",
                    "source": "signoz",
                    "category": "latency",
                    "detail": f"Span '{name}' p95={p95:.1f}s — monitor",
                    "span_name": name,
                    "p95_seconds": p95,
                })

    for row in error_rates:
        if len(row) >= 4:
            service, total, errors, pct = row[0], row[1], row[2], float(row[3])
            if pct > 5:
                report["issues"].append({
                    "severity": "HIGH",
                    "source": "signoz",
                    "category": "errors",
                    "detail": f"Service '{service}' error rate {pct:.1f}% ({errors}/{total})",
                    "service": service,
                    "error_pct": pct,
                })

    for row in tool_errors:
        if len(row) >= 2:
            tool_name, count = row[0], int(row[1])
            if count > 0:
                report["issues"].append({
                    "severity": "HIGH",
                    "source": "signoz",
                    "category": "tool_error",
                    "detail": f"Tool '{tool_name}' threw {count} errors in last 6h",
                    "tool": tool_name.replace("tool.", ""),
                    "error_count": count,
                    "example_trace": row[2] if len(row) > 2 else None,
                })

    # Check LLM latency trend (is it getting worse over time?)
    if len(llm_trend) >= 2:
        latest_p95 = float(llm_trend[0][2]) if llm_trend[0][2] != '\\N' else 0
        oldest_p95 = float(llm_trend[-1][2]) if llm_trend[-1][2] != '\\N' else 0
        if latest_p95 > oldest_p95 * 1.2:
            report["issues"].append({
                "severity": "MEDIUM",
                "source": "signoz",
                "category": "latency_trend",
                "detail": f"LLM call latency trending up: {oldest_p95:.1f}s → {latest_p95:.1f}s",
                "trend_pct": round((latest_p95 / oldest_p95 - 1) * 100),
            })

    print(f"  Signoz: {len(slow_spans)} span types, "
          f"{sum(int(r[2]) for r in error_rates if len(r)>2 and r[2].isdigit())} total errors")

except Exception as e:
    report["sources"]["signoz"] = {"status": "error", "error": str(e)}
    print(f"  Signoz: UNAVAILABLE ({e})")


# ─────────────────────────────────────────────────────────────────
# SOURCE 2: POSTGRESQL — Investigation Quality Metrics
# ─────────────────────────────────────────────────────────────────
print("Reading PostgreSQL investigation data...")
try:
    def pg_query(sql):
        result = subprocess.run(
            ["docker", "compose", "exec", "-T", "postgres",
             "psql", "-U", "zovark", "-d", "zovark",
             "-t", "-c", sql],
            capture_output=True, text=True, timeout=30
        )
        return result.stdout.strip()

    tenant_id_raw = pg_query(
        "SELECT DISTINCT tenant_id FROM agent_tasks LIMIT 1;"
    ).strip()
    tenant_id = tenant_id_raw.split('\n')[0].strip() if tenant_id_raw else None

    if tenant_id:
        def pg_tenant(sql):
            wrapped = f"""
BEGIN;
SET LOCAL app.current_tenant = '{tenant_id}';
{sql}
COMMIT;"""
            return pg_query(wrapped)

        # 2a. Verdict distribution (last 24h)
        verdict_dist = pg_tenant("""
SELECT output->>'verdict' as verdict, COUNT(*) as count
FROM agent_tasks
WHERE status = 'completed'
AND created_at > NOW() - INTERVAL '24 hours'
GROUP BY verdict
ORDER BY count DESC;""")

        # 2b. Error rate by task type
        error_by_type = pg_tenant("""
SELECT task_type,
       COUNT(*) as total,
       SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) as errors,
       ROUND(AVG(EXTRACT(EPOCH FROM (updated_at - created_at))), 2) as avg_duration_s
FROM agent_tasks
WHERE created_at > NOW() - INTERVAL '24 hours'
GROUP BY task_type
ORDER BY errors DESC
LIMIT 10;""")

        # 2c. Risk score distribution — are we over-scoring or under-scoring?
        risk_dist = pg_tenant("""
SELECT
    CASE
        WHEN (output->>'risk_score')::int >= 80 THEN 'critical_80_100'
        WHEN (output->>'risk_score')::int >= 60 THEN 'high_60_79'
        WHEN (output->>'risk_score')::int >= 40 THEN 'medium_40_59'
        WHEN (output->>'risk_score')::int >= 20 THEN 'low_20_39'
        ELSE 'minimal_0_19'
    END as bucket,
    COUNT(*) as count
FROM agent_tasks
WHERE status = 'completed'
AND output->>'risk_score' IS NOT NULL
AND created_at > NOW() - INTERVAL '24 hours'
GROUP BY bucket
ORDER BY bucket;""")

        # 2d. Path distribution (A = template, C = LLM)
        path_dist_pg = pg_tenant("""
SELECT output->>'execution_mode' as path, COUNT(*) as count
FROM agent_tasks
WHERE status = 'completed'
AND created_at > NOW() - INTERVAL '24 hours'
GROUP BY path;""")

        # 2e. Investigations that took longest (potential optimization targets)
        slowest_investigations = pg_tenant("""
SELECT task_type,
       output->>'execution_mode' as path,
       ROUND(EXTRACT(EPOCH FROM (updated_at - created_at)), 1) as duration_s,
       output->>'verdict' as verdict
FROM agent_tasks
WHERE status = 'completed'
AND created_at > NOW() - INTERVAL '24 hours'
ORDER BY duration_s DESC
LIMIT 10;""")

        # 2f. Template coverage gaps
        template_coverage = pg_tenant("""
SELECT
    t.task_type,
    COUNT(DISTINCT tmpl.id) as template_count,
    COUNT(DISTINCT t.id) as investigation_count,
    ROUND(COUNT(DISTINCT CASE WHEN t.output->>'execution_mode' = 'template'
                              THEN t.id END) * 100.0
          / NULLIF(COUNT(DISTINCT t.id), 0), 1) as path_a_rate_pct
FROM agent_tasks t
LEFT JOIN investigation_templates tmpl
    ON tmpl.task_type = t.task_type AND tmpl.status = 'approved'
WHERE t.status = 'completed'
AND t.created_at > NOW() - INTERVAL '24 hours'
GROUP BY t.task_type
ORDER BY path_a_rate_pct ASC NULLS FIRST
LIMIT 10;""")

        # 2g. Suspicious → true_positive escalation failures
        escalation_failures = pg_tenant("""
SELECT task_type, COUNT(*) as suspicious_count
FROM agent_tasks
WHERE status = 'completed'
AND output->>'verdict' = 'suspicious'
AND (output->>'risk_score')::int >= 65
AND created_at > NOW() - INTERVAL '24 hours'
GROUP BY task_type
ORDER BY suspicious_count DESC;""")

        report["sources"]["postgres"] = {
            "status": "ok",
            "tenant_id": tenant_id,
            "verdict_distribution": verdict_dist,
            "error_by_type": error_by_type,
            "risk_distribution": risk_dist,
            "path_distribution": path_dist_pg,
            "slowest_investigations": slowest_investigations,
            "template_coverage": template_coverage,
            "escalation_failures": escalation_failures,
        }

        # Generate issues from Postgres data
        for line in escalation_failures.strip().split('\n'):
            parts = [p.strip() for p in line.split('|') if p.strip()]
            if len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) > 2:
                report["issues"].append({
                    "severity": "HIGH",
                    "source": "postgres",
                    "category": "verdict_calibration",
                    "detail": f"Task type '{parts[0]}' has {parts[1]} suspicious verdicts "
                              f"with risk_score >= 65 — risk floor may need raising",
                    "task_type": parts[0],
                    "count": int(parts[1]),
                })

        for line in template_coverage.strip().split('\n'):
            parts = [p.strip() for p in line.split('|') if p.strip()]
            if len(parts) >= 4:
                try:
                    task_type = parts[0]
                    path_a_rate = float(parts[3].replace('%', ''))
                    tmpl_count = int(parts[1]) if parts[1].isdigit() else 0
                    if path_a_rate < 50 and tmpl_count < 3:
                        report["issues"].append({
                            "severity": "MEDIUM",
                            "source": "postgres",
                            "category": "template_gap",
                            "detail": f"Task type '{task_type}' Path A rate={path_a_rate:.0f}%, "
                                      f"only {tmpl_count} templates — add more",
                            "task_type": task_type,
                            "path_a_rate": path_a_rate,
                            "template_count": tmpl_count,
                        })
                except (ValueError, IndexError):
                    pass

        print(f"  Postgres: investigation data loaded for tenant {tenant_id}")
    else:
        print("  Postgres: no tenant found")

except Exception as e:
    report["sources"]["postgres"] = {"status": "error", "error": str(e)}
    print(f"  Postgres: UNAVAILABLE ({e})")


# ─────────────────────────────────────────────────────────────────
# SOURCE 3: TEMPORAL — Workflow Health
# ─────────────────────────────────────────────────────────────────
print("Reading Temporal workflow data...")
try:
    temporal_result = subprocess.run(
        ["docker", "compose", "exec", "-T", "temporal",
         "tctl", "--namespace", "default",
         "workflow", "list", "--status", "Failed",
         "--pagesize", "20", "-o", "json"],
        capture_output=True, text=True, timeout=30
    )

    failed_workflows = []
    if temporal_result.returncode == 0 and temporal_result.stdout:
        try:
            wf_data = json.loads(temporal_result.stdout)
            failed_workflows = wf_data if isinstance(wf_data, list) else []
        except json.JSONDecodeError:
            pass

    running_result = subprocess.run(
        ["docker", "compose", "exec", "-T", "temporal",
         "tctl", "--namespace", "default",
         "workflow", "list", "--status", "Running",
         "--pagesize", "5", "-o", "json"],
        capture_output=True, text=True, timeout=30
    )
    running_count = 0
    if running_result.returncode == 0 and running_result.stdout:
        try:
            running_data = json.loads(running_result.stdout)
            running_count = len(running_data) if isinstance(running_data, list) else 0
        except:
            pass

    report["sources"]["temporal"] = {
        "status": "ok",
        "failed_workflow_count": len(failed_workflows),
        "running_workflow_count": running_count,
        "failed_workflow_types": list(set(
            wf.get("type", {}).get("name", "unknown")
            for wf in failed_workflows
        )),
    }

    if len(failed_workflows) > 5:
        report["issues"].append({
            "severity": "HIGH",
            "source": "temporal",
            "category": "workflow_failures",
            "detail": f"{len(failed_workflows)} failed workflows in Temporal — "
                      f"investigate worker crash recovery",
            "count": len(failed_workflows),
            "workflow_types": report["sources"]["temporal"]["failed_workflow_types"],
        })

    print(f"  Temporal: {len(failed_workflows)} failed, {running_count} running")

except Exception as e:
    report["sources"]["temporal"] = {"status": "error", "error": str(e)}
    print(f"  Temporal: {e}")


# ─────────────────────────────────────────────────────────────────
# SOURCE 4: OLLAMA — Model Performance
# ─────────────────────────────────────────────────────────────────
print("Reading Ollama model stats...")
try:
    with httpx.Client(timeout=10) as client:
        tags_resp = client.get("http://localhost:11434/api/tags")
        models = tags_resp.json().get("models", []) if tags_resp.status_code == 200 else []

        ps_resp = client.get("http://localhost:11434/api/ps")
        running = ps_resp.json().get("models", []) if ps_resp.status_code == 200 else []

    model_info = {}
    for m in models:
        name = m.get("name", "")
        size_gb = m.get("size", 0) / 1e9
        model_info[name] = {
            "size_gb": round(size_gb, 2),
            "modified_at": m.get("modified_at", ""),
        }

    report["sources"]["ollama"] = {
        "status": "ok",
        "models_available": list(model_info.keys()),
        "models_loaded": [m.get("name") for m in running],
        "model_details": model_info,
    }

    expected = ["llama3.1:8b", "llama3.2:3b"]
    for m in expected:
        if not any(m in k for k in model_info.keys()):
            report["issues"].append({
                "severity": "HIGH",
                "source": "ollama",
                "category": "model_missing",
                "detail": f"Expected model '{m}' not found in Ollama",
                "model": m,
            })

    print(f"  Ollama: {list(model_info.keys())} | loaded: {[m.get('name') for m in running]}")

except Exception as e:
    report["sources"]["ollama"] = {"status": "error", "error": str(e)}
    print(f"  Ollama: {e}")


# ─────────────────────────────────────────────────────────────────
# SOURCE 5: CODE GRAPH RAG — Codebase Intelligence
# ─────────────────────────────────────────────────────────────────
print("Reading Code Graph RAG...")
try:
    cgr_result = subprocess.run(
        ["python3", "-c", """
import sys
sys.path.insert(0, '.')
try:
    from code_graph_rag import query_graph
    
    results = {
        "most_complex": query_graph("functions with highest cyclomatic complexity"),
        "most_connected": query_graph("functions called by the most other functions"),
        "no_tests": query_graph("functions with no test coverage"),
        "recent_changes": query_graph("recently modified files"),
    }
    import json
    print(json.dumps(results))
except ImportError:
    print('{"error": "CGR not available"}')
"""],
        capture_output=True, text=True, timeout=60
    )

    if cgr_result.returncode == 0 and cgr_result.stdout:
        try:
            cgr_data = json.loads(cgr_result.stdout)
            report["sources"]["code_graph_rag"] = {"status": "ok", "data": cgr_data}
            print(f"  Code Graph RAG: data loaded")
        except:
            report["sources"]["code_graph_rag"] = {
                "status": "partial", "raw": cgr_result.stdout[:500]
            }
            print(f"  Code Graph RAG: partial data")
    else:
        report["sources"]["code_graph_rag"] = {
            "status": "unavailable",
            "note": "Query Code Graph RAG manually via MCP before modifying any source file"
        }
        print(f"  Code Graph RAG: use MCP tools to query before changes")

except Exception as e:
    report["sources"]["code_graph_rag"] = {"status": "error", "error": str(e)}
    print(f"  Code Graph RAG: {e}")


# ─────────────────────────────────────────────────────────────────
# SOURCE 6: TEST COVERAGE — Find gaps
# ─────────────────────────────────────────────────────────────────
print("Reading test coverage...")
try:
    cov_result = subprocess.run(
        ["docker", "compose", "exec", "-T", "worker",
         "python", "-m", "pytest", "worker/tests/",
         "--cov=worker", "--cov-report=json",
         "--no-header", "-q", "--tb=no"],
        capture_output=True, text=True, timeout=300
    )

    coverage_data = {}
    if os.path.exists(".coverage.json"):
        with open(".coverage.json") as f:
            cov_json = json.load(f)
            for filepath, data in cov_json.get("files", {}).items():
                pct = data.get("summary", {}).get("percent_covered", 100)
                if pct < 80:
                    coverage_data[filepath] = round(pct, 1)

    report["sources"]["test_coverage"] = {
        "status": "ok",
        "low_coverage_files": dict(sorted(
            coverage_data.items(), key=lambda x: x[1]
        )[:15]),
    }

    for filepath, pct in list(coverage_data.items())[:5]:
        if pct < 60:
            report["issues"].append({
                "severity": "MEDIUM",
                "source": "test_coverage",
                "category": "low_coverage",
                "detail": f"File '{filepath}' has {pct:.0f}% test coverage — add tests",
                "file": filepath,
                "coverage_pct": pct,
            })

    print(f"  Coverage: {len(coverage_data)} files below 80%")

except Exception as e:
    report["sources"]["test_coverage"] = {"status": "error", "error": str(e)}
    print(f"  Coverage: {e}")


# ─────────────────────────────────────────────────────────────────
# SOURCE 7: RED TEAM STATUS
# ─────────────────────────────────────────────────────────────────
print("Reading red team status...")
try:
    bypass_files = [f for f in os.listdir("autoresearch/redteam_nightly/bypasses/")
                    if f.endswith(".json")] if os.path.exists(
                        "autoresearch/redteam_nightly/bypasses/") else []
    vector_count = 0
    if os.path.exists("autoresearch/redteam_nightly/attack_vectors.json"):
        with open("autoresearch/redteam_nightly/attack_vectors.json") as f:
            vector_count = len(json.load(f))

    report["sources"]["red_team"] = {
        "status": "ok",
        "total_vectors": vector_count,
        "open_bypasses": len(bypass_files),
        "bypass_files": bypass_files,
    }

    if bypass_files:
        report["issues"].append({
            "severity": "CRITICAL",
            "source": "red_team",
            "category": "open_bypass",
            "detail": f"{len(bypass_files)} open bypass(es) — MUST FIX before other work",
            "files": bypass_files,
        })

    print(f"  Red team: {vector_count} vectors, {len(bypass_files)} open bypasses")

except Exception as e:
    report["sources"]["red_team"] = {"status": "error", "error": str(e)}
    print(f"  Red team: {e}")


# ─────────────────────────────────────────────────────────────────
# BUILD PRIORITY QUEUE
# Rank all issues: CRITICAL > HIGH > MEDIUM
severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
category_impact = {
    "open_bypass": 10,
    "workflow_failures": 9,
    "tool_error": 8,
    "errors": 8,
    "verdict_calibration": 7,
    "latency": 6,
    "latency_trend": 5,
    "template_gap": 4,
    "model_missing": 9,
    "low_coverage": 2,
}

report["issues"].sort(key=lambda x: (
    severity_order.get(x["severity"], 99),
    -category_impact.get(x["category"], 0),
    -x.get("count", x.get("error_count", x.get("error_pct", 0))),
))

report["priority_queue"] = report["issues"][:10]

# Save full report
output_path = os.path.join(OUTPUT_DIR, f"cycle_{CYCLE}_telemetry.json")
with open(output_path, "w") as f:
    json.dump(report, f, indent=2)

# Print summary
print(f"\n{'='*65}")
print(f"TELEMETRY SUMMARY — CYCLE {CYCLE}")
print(f"{'='*65}")
print(f"\nDATA SOURCES:")
for source, data in report["sources"].items():
    status = data.get("status", "unknown")
    icon = "✅" if status == "ok" else "⚠️" if status == "partial" else "❌"
    print(f"  {icon} {source}: {status}")

print(f"\nISSUES FOUND: {len(report['issues'])}")
print(f"\nPRIORITY QUEUE (top 10 — work on these first):")
for i, issue in enumerate(report["priority_queue"], 1):
    print(f"  {i}. [{issue['severity']}] {issue['category'].upper()}")
    print(f"     {issue['detail']}")
print(f"\nFull report: {output_path}")
print(f"{'='*65}\n")
