#!/usr/bin/env python3
"""Collect Cycle 2 telemetry"""
import json, httpx

CH_URL = 'http://zovark-clickhouse:8123'

def ch_query(sql):
    try:
        resp = httpx.post(CH_URL, content=sql, params={'database': 'signoz_traces'}, timeout=30)
        return resp.json() if resp.status_code == 200 else {}
    except Exception as e:
        return {'error': str(e)}

telemetry = {
    'cycle': 2,
    'spans_last_6h': ch_query('SELECT name, quantile(0.95)(durationNano) / 1e9 AS p95, count() AS calls FROM signoz_index_v2 WHERE timestamp > now() - INTERVAL 6 HOUR AND name NOT LIKE \"%health%\" GROUP BY name ORDER BY p95 DESC LIMIT 15 FORMAT JSON'),
    'errors_last_6h': ch_query('SELECT name, count() AS errors FROM signoz_index_v2 WHERE statusCode = 2 AND timestamp > now() - INTERVAL 6 HOUR GROUP BY name ORDER BY errors DESC LIMIT 10 FORMAT JSON'),
    'tools_last_6h': ch_query('SELECT name, quantile(0.95)(durationNano) / 1e6 AS p95_ms, count() AS calls FROM signoz_index_v2 WHERE name LIKE \"tool.%\" AND timestamp > now() - INTERVAL 6 HOUR GROUP BY name ORDER BY p95_ms DESC LIMIT 15 FORMAT JSON'),
    'llm_trend': ch_query('SELECT toStartOfHour(timestamp) AS hour, avg(durationNano) / 1e9 AS avg_seconds, quantile(0.95)(durationNano) / 1e9 AS p95_seconds, count() AS calls FROM signoz_index_v2 WHERE name = \"llm.call\" AND timestamp > now() - INTERVAL 24 HOUR GROUP BY hour ORDER BY hour DESC LIMIT 24 FORMAT JSON'),
    'path_distribution': ch_query('SELECT tagMap[\'execution_mode\'] AS path, count() AS count FROM signoz_index_v2 WHERE name = \'investigation.complete\' AND timestamp > now() - INTERVAL 24 HOUR GROUP BY path FORMAT JSON')
}

with open('cycle_2_telemetry.json', 'w') as f:
    json.dump(telemetry, f, indent=2)

print(json.dumps(telemetry, indent=2))
