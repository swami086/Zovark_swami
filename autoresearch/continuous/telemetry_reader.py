#!/usr/bin/env python3
"""
Telemetry reader. Runs at cycle start. Queries all live data sources.
Produces priority queue of issues to fix this cycle.
"""
import json, os, sys, time, subprocess
CYCLE = int(sys.argv[1]) if len(sys.argv) > 1 else 1
OUT = "autoresearch/continuous"
os.makedirs(OUT, exist_ok=True)

try:
    import httpx
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "httpx", "-q"])
    import httpx

report = {
    "cycle": CYCLE,
    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
    "sources": {},
    "issues": [],
    "priority_queue": [],
}

# ── SOURCE 1: SIGNOZ ──────────────────────────────────────────────
print("[telemetry] Reading Signoz traces...")
try:
    def ch(sql):
        r = httpx.post("http://localhost:8123", content=sql,
                       params={"database": "signoz_traces"}, timeout=20)
        return [l.split("\t") for l in r.text.strip().split("\n") if l] if r.status_code == 200 else []

    slow = ch("""
        SELECT name,
               quantile(0.95)(durationNano)/1e9 AS p95,
               quantile(0.50)(durationNano)/1e9 AS p50,
               count() AS n,
               countIf(statusCode=2) AS errs
        FROM signoz_index_v2
        WHERE timestamp > now()-INTERVAL 6 HOUR
          AND name NOT LIKE '%health%'
        GROUP BY name ORDER BY p95 DESC LIMIT 20
    """)
    errs = ch("""
        SELECT serviceName,
               count() AS total,
               countIf(statusCode=2) AS errors,
               round(countIf(statusCode=2)*100.0/count(),2) AS pct
        FROM signoz_index_v2
        WHERE timestamp > now()-INTERVAL 6 HOUR
        GROUP BY serviceName ORDER BY pct DESC
    """)
    tool_errs = ch("""
        SELECT name, count() AS n, any(traceID) AS tid
        FROM signoz_index_v2
        WHERE statusCode=2 AND name LIKE 'tool.%'
          AND timestamp > now()-INTERVAL 6 HOUR
        GROUP BY name ORDER BY n DESC LIMIT 10
    """)
    llm_trend = ch("""
        SELECT toStartOfHour(timestamp) AS h,
               avg(durationNano)/1e9 AS avg_s,
               quantile(0.95)(durationNano)/1e9 AS p95_s,
               count() AS n
        FROM signoz_index_v2
        WHERE name='llm.call'
          AND timestamp > now()-INTERVAL 24 HOUR
        GROUP BY h ORDER BY h DESC LIMIT 12
    """)
    path_dist = ch("""
        SELECT tagMap['execution_mode'] AS mode, count() AS n
        FROM signoz_index_v2
        WHERE name='investigation.complete'
          AND timestamp > now()-INTERVAL 6 HOUR
        GROUP BY mode
    """)

    report["sources"]["signoz"] = {
        "status": "ok",
        "slow_spans": slow[:10],
        "service_errors": errs,
        "tool_errors": tool_errs,
        "llm_trend": llm_trend[:6],
        "path_distribution": path_dist,
    }

    for row in slow:
        if len(row) >= 2:
            try:
                p95 = float(row[1])
                if p95 > 30:
                    report["issues"].append({"severity":"HIGH","source":"signoz",
                        "category":"latency","detail":f"Span '{row[0]}' p95={p95:.1f}s",
                        "span":row[0],"p95":p95})
                elif p95 > 10:
                    report["issues"].append({"severity":"MEDIUM","source":"signoz",
                        "category":"latency","detail":f"Span '{row[0]}' p95={p95:.1f}s",
                        "span":row[0],"p95":p95})
            except: pass

    for row in errs:
        if len(row) >= 4:
            try:
                pct = float(row[3])
                if pct > 5:
                    report["issues"].append({"severity":"HIGH","source":"signoz",
                        "category":"errors",
                        "detail":f"Service '{row[0]}' error rate {pct:.1f}%",
                        "service":row[0],"pct":pct})
            except: pass

    for row in tool_errs:
        if len(row) >= 2:
            try:
                n = int(row[1])
                if n > 0:
                    report["issues"].append({"severity":"HIGH","source":"signoz",
                        "category":"tool_error",
                        "detail":f"Tool '{row[0]}' threw {n} errors in 6h",
                        "tool":row[0].replace("tool.",""),"count":n,
                        "trace":row[2] if len(row)>2 else None})
            except: pass

    print(f"  Signoz: {len(slow)} span types, {len(tool_errs)} tool errors")
except Exception as e:
    report["sources"]["signoz"] = {"status":"error","error":str(e)}
    print(f"  Signoz: {e}")


# ── SOURCE 2: POSTGRES ────────────────────────────────────────────
print("[telemetry] Reading PostgreSQL...")
try:
    def pg(sql):
        r = subprocess.run(
            ["docker","compose","exec","-T","postgres",
             "psql","-U","zovark","-d","zovark","-t","-c",sql],
            capture_output=True, text=True, timeout=30)
        return r.stdout.strip()

    tid = pg("SELECT DISTINCT tenant_id FROM agent_tasks LIMIT 1;").split('\n')[0].strip()

    def pgt(sql):
        return pg(f"BEGIN;SET LOCAL app.current_tenant='{tid}';{sql}COMMIT;")

    if tid:
        v_dist    = pgt("SELECT output->>'verdict',COUNT(*) FROM agent_tasks WHERE status='completed' AND created_at>NOW()-INTERVAL '24 hours' GROUP BY 1 ORDER BY 2 DESC;")
        path_pg   = pgt("SELECT output->>'execution_mode',COUNT(*) FROM agent_tasks WHERE status='completed' AND created_at>NOW()-INTERVAL '24 hours' GROUP BY 1;")
        slow_inv  = pgt("SELECT task_type,output->>'execution_mode',ROUND(EXTRACT(EPOCH FROM(updated_at-created_at)),1) FROM agent_tasks WHERE status='completed' AND created_at>NOW()-INTERVAL '24 hours' ORDER BY 3 DESC LIMIT 5;")
        esc_fail  = pgt("SELECT task_type,COUNT(*) FROM agent_tasks WHERE status='completed' AND output->>'verdict'='suspicious' AND (output->>'risk_score')::int>=65 AND created_at>NOW()-INTERVAL '24 hours' GROUP BY 1 ORDER BY 2 DESC;")
        tmpl_cov  = pgt("SELECT t.task_type,COUNT(DISTINCT tmpl.id) AS tmpls,COUNT(DISTINCT t.id) AS invests FROM agent_tasks t LEFT JOIN investigation_templates tmpl ON tmpl.task_type=t.task_type AND tmpl.status='approved' WHERE t.status='completed' AND t.created_at>NOW()-INTERVAL '24 hours' GROUP BY t.task_type ORDER BY tmpls ASC LIMIT 10;")
        err_types = pgt("SELECT task_type,COUNT(*) FROM agent_tasks WHERE status='error' AND created_at>NOW()-INTERVAL '24 hours' GROUP BY 1 ORDER BY 2 DESC LIMIT 5;")

        report["sources"]["postgres"] = {
            "status":"ok","tenant_id":tid,
            "verdict_dist":v_dist,"path_dist":path_pg,
            "slowest":slow_inv,"escalation_failures":esc_fail,
            "template_coverage":tmpl_cov,"error_types":err_types,
        }

        for line in esc_fail.split('\n'):
            p = [x.strip() for x in line.split('|') if x.strip()]
            if len(p)>=2 and p[1].isdigit() and int(p[1])>2:
                report["issues"].append({"severity":"HIGH","source":"postgres",
                    "category":"verdict_calibration",
                    "detail":f"'{p[0]}' has {p[1]} suspicious verdicts with risk>=65",
                    "task_type":p[0],"count":int(p[1])})

        for line in tmpl_cov.split('\n'):
            p = [x.strip() for x in line.split('|') if x.strip()]
            if len(p)>=2:
                try:
                    if int(p[1])==0:
                        report["issues"].append({"severity":"MEDIUM","source":"postgres",
                            "category":"template_gap",
                            "detail":f"'{p[0]}' has 0 templates — add at least 1",
                            "task_type":p[0]})
                except: pass

        for line in err_types.split('\n'):
            p = [x.strip() for x in line.split('|') if x.strip()]
            if len(p)>=2 and p[1].isdigit() and int(p[1])>0:
                report["issues"].append({"severity":"HIGH","source":"postgres",
                    "category":"investigation_errors",
                    "detail":f"Task type '{p[0]}' had {p[1]} errors in 24h",
                    "task_type":p[0],"count":int(p[1])})

        print(f"  Postgres: tenant {tid}, data loaded")
    else:
        print("  Postgres: no tenant found")
except Exception as e:
    report["sources"]["postgres"] = {"status":"error","error":str(e)}
    print(f"  Postgres: {e}")


# ── SOURCE 3: TEMPORAL ───────────────────────────────────────────
print("[telemetry] Reading Temporal...")
try:
    r = subprocess.run(
        ["docker","compose","exec","-T","temporal",
         "tctl","--namespace","default","workflow","list",
         "--status","Failed","--pagesize","20","-o","json"],
        capture_output=True, text=True, timeout=30)
    failed = []
    if r.returncode==0 and r.stdout:
        try: failed = json.loads(r.stdout) if r.stdout.strip().startswith('[') else []
        except: pass
    report["sources"]["temporal"] = {
        "status":"ok","failed_count":len(failed),
        "types":list(set(w.get("type",{}).get("name","?") for w in failed)),
    }
    if len(failed)>3:
        report["issues"].append({"severity":"HIGH","source":"temporal",
            "category":"workflow_failures",
            "detail":f"{len(failed)} failed workflows — check worker logs",
            "count":len(failed)})
    print(f"  Temporal: {len(failed)} failed workflows")
except Exception as e:
    report["sources"]["temporal"] = {"status":"error","error":str(e)}
    print(f"  Temporal: {e}")


# ── SOURCE 4: OLLAMA ─────────────────────────────────────────────
print("[telemetry] Reading Ollama...")
try:
    with httpx.Client(timeout=10) as c:
        tags = c.get("http://localhost:11434/api/tags").json().get("models",[])
        loaded = c.get("http://localhost:11434/api/ps").json().get("models",[])
    names = [m.get("name","") for m in tags]
    report["sources"]["ollama"] = {
        "status":"ok","available":names,
        "loaded":[m.get("name") for m in loaded],
    }
    for exp in ["llama3.1:8b","llama3.2:3b"]:
        if not any(exp in n for n in names):
            report["issues"].append({"severity":"HIGH","source":"ollama",
                "category":"model_missing",
                "detail":f"Model '{exp}' not found","model":exp})
    print(f"  Ollama: {names}")
except Exception as e:
    report["sources"]["ollama"] = {"status":"error","error":str(e)}
    print(f"  Ollama: {e}")


# ── SOURCE 5: RED TEAM STATUS ─────────────────────────────────────
print("[telemetry] Reading red team status...")
try:
    bp_dir = "autoresearch/redteam_nightly/bypasses"
    bps = [f for f in os.listdir(bp_dir) if f.endswith(".json")] if os.path.exists(bp_dir) else []
    vec_count = 0
    if os.path.exists("autoresearch/redteam_nightly/attack_vectors.json"):
        vec_count = len(json.load(open("autoresearch/redteam_nightly/attack_vectors.json")))
    report["sources"]["red_team"] = {"status":"ok","vectors":vec_count,"bypasses":len(bps)}
    if bps:
        report["issues"].append({"severity":"CRITICAL","source":"red_team",
            "category":"open_bypass",
            "detail":f"{len(bps)} open bypass(es) — fix before anything else",
            "files":bps})
    print(f"  Red team: {vec_count} vectors, {len(bps)} open bypasses")
except Exception as e:
    report["sources"]["red_team"] = {"status":"error","error":str(e)}
    print(f"  Red team: {e}")


# ── SOURCE 6: TEST COVERAGE ───────────────────────────────────────
print("[telemetry] Reading test coverage...")
try:
    r = subprocess.run(
        ["docker","compose","exec","-T","worker",
         "python","-m","pytest","worker/tests/",
         "--cov=worker","--cov-report=json",
         "-q","--tb=no","--no-header"],
        capture_output=True, text=True, timeout=300)
    low = {}
    cov_file = ".coverage.json"
    if os.path.exists(cov_file):
        data = json.load(open(cov_file))
        for fp,d in data.get("files",{}).items():
            pct = d.get("summary",{}).get("percent_covered",100)
            if pct < 70:
                low[fp] = round(pct,1)
    report["sources"]["coverage"] = {
        "status":"ok",
        "low_files": dict(sorted(low.items(),key=lambda x:x[1])[:10])
    }
    for fp,pct in list(low.items())[:3]:
        if pct < 50:
            report["issues"].append({"severity":"MEDIUM","source":"coverage",
                "category":"low_coverage",
                "detail":f"'{fp}' at {pct:.0f}% coverage","file":fp,"pct":pct})
    print(f"  Coverage: {len(low)} files below 70%")
except Exception as e:
    report["sources"]["coverage"] = {"status":"error","error":str(e)}
    print(f"  Coverage: {e}")


# ── PRIORITY QUEUE ────────────────────────────────────────────────
sev = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
imp = {"open_bypass":10,"workflow_failures":9,"model_missing":9,"tool_error":8,
       "errors":8,"investigation_errors":8,"verdict_calibration":7,
       "latency":6,"template_gap":4,"low_coverage":2}
report["issues"].sort(key=lambda x:(
    sev.get(x["severity"],9),
    -imp.get(x["category"],0),
    -x.get("count",x.get("pct",0)),
))
report["priority_queue"] = report["issues"][:8]

json.dump(report, open(f"{OUT}/cycle_{CYCLE}_telemetry.json","w"), indent=2)

print(f"\n{'='*60}")
print(f"TELEMETRY — CYCLE {CYCLE} — {report['timestamp']}")
print(f"{'='*60}")
for src,d in report["sources"].items():
    icon = "OK" if d.get("status")=="ok" else "ERR"
    print(f"  [{icon}] {src}")
print(f"\nISSUES: {len(report['issues'])} found")
print(f"PRIORITY QUEUE:")
for i,iss in enumerate(report["priority_queue"],1):
    print(f"  {i}. [{iss['severity']}] {iss['category']}: {iss['detail'][:80]}")
print(f"{'='*60}\n")
