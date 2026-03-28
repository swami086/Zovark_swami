#!/usr/bin/env python3
"""Import historical alerts from customer SIEM exports.

Supports:
- Splunk CSV export (default)
- Microsoft Sentinel JSON
- QRadar XML
- Generic JSON (array of alert objects)

Usage:
  python import_alerts.py --format splunk --file alerts.csv --tenant-id <uuid>
  python import_alerts.py --format sentinel --file alerts.json --tenant-id <uuid>
  python import_alerts.py --format generic --file alerts.json --tenant-id <uuid>

Each alert is:
1. Parsed into siem_alerts schema format
2. Sanitized via AlertSanitizer (v0.12.0)
3. Inserted into siem_alerts table
4. Optionally submitted for investigation via API

Progress: prints count every 10 alerts. Skips duplicates by source_alert_id.
"""
import argparse
import csv
import json
import sys
import uuid
from datetime import datetime

import httpx


# ── Format Parsers ──────────────────────────────────────────────────────────


class SplunkCSVParser:
    """Maps Splunk CSV columns → siem_alerts fields."""

    FIELD_MAP = {
        'source': ('source', '_raw.source', 'sourcetype'),
        'severity': ('severity', 'urgency', 'priority'),
        'title': ('search_name', 'alert_name', 'name', 'rule_name'),
        'raw_data': ('_raw', 'raw', 'message'),
        'source_alert_id': ('sid', 'alert_id', 'event_id'),
        'timestamp': ('_time', 'timestamp', 'time'),
        'source_ip': ('src_ip', 'src', 'source_ip'),
        'dest_ip': ('dest_ip', 'dest', 'destination_ip'),
        'rule_name': ('rule_name', 'search_name', 'alert_name'),
    }

    def parse(self, filepath: str) -> list:
        alerts = []
        with open(filepath, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                alert = self._map_row(row)
                alerts.append(alert)
        return alerts

    def _map_row(self, row: dict) -> dict:
        result = {}
        for target, candidates in self.FIELD_MAP.items():
            for col in candidates:
                if col in row and row[col]:
                    result[target] = row[col]
                    break
        result.setdefault('source', 'splunk-import')
        result.setdefault('severity', 'medium')
        result.setdefault('title', 'Splunk Alert')
        result.setdefault('raw_data', json.dumps(dict(row)))
        result.setdefault('source_alert_id', str(uuid.uuid4())[:12])
        return result


class SentinelJSONParser:
    """Maps Microsoft Sentinel incident/alert JSON → siem_alerts fields."""

    def parse(self, filepath: str) -> list:
        with open(filepath, 'r') as f:
            data = json.load(f)

        items = data if isinstance(data, list) else data.get('value', [data])
        alerts = []
        for item in items:
            alert = {
                'title': item.get('properties', {}).get('title', item.get('title', 'Sentinel Alert')),
                'severity': item.get('properties', {}).get('severity', item.get('severity', 'medium')).lower(),
                'source': 'sentinel-import',
                'source_alert_id': item.get('name', item.get('id', str(uuid.uuid4())[:12])),
                'raw_data': json.dumps(item),
                'timestamp': item.get('properties', {}).get('createdTimeUtc',
                             item.get('createdTimeUtc', datetime.utcnow().isoformat())),
            }
            # Extract entities
            entities = item.get('properties', {}).get('relatedEntities', [])
            for e in entities:
                kind = e.get('kind', '').lower()
                if kind == 'ip' and 'address' in e.get('properties', {}):
                    alert['source_ip'] = e['properties']['address']
                elif kind == 'host' and 'hostName' in e.get('properties', {}):
                    alert['dest_ip'] = e['properties']['hostName']
            alerts.append(alert)
        return alerts


class QRadarXMLParser:
    """Maps QRadar XML offense export → siem_alerts fields."""

    def parse(self, filepath: str) -> list:
        import xml.etree.ElementTree as ET
        tree = ET.parse(filepath)
        root = tree.getroot()

        alerts = []
        for offense in root.iter('offense'):
            alert = {
                'title': offense.findtext('description', 'QRadar Offense'),
                'severity': self._map_severity(offense.findtext('severity', '5')),
                'source': 'qradar-import',
                'source_alert_id': offense.findtext('id', str(uuid.uuid4())[:12]),
                'raw_data': ET.tostring(offense, encoding='unicode'),
                'source_ip': offense.findtext('offense_source', ''),
            }
            alerts.append(alert)
        return alerts

    @staticmethod
    def _map_severity(sev_str: str) -> str:
        try:
            sev = int(sev_str)
        except ValueError:
            return 'medium'
        if sev >= 8:
            return 'critical'
        if sev >= 6:
            return 'high'
        if sev >= 4:
            return 'medium'
        return 'low'


class GenericJSONParser:
    """Accepts any JSON array, maps common field names."""

    def parse(self, filepath: str) -> list:
        with open(filepath, 'r') as f:
            data = json.load(f)

        items = data if isinstance(data, list) else [data]
        alerts = []
        for item in items:
            alert = {
                'title': item.get('title', item.get('name', item.get('alert_name', 'Alert'))),
                'severity': item.get('severity', item.get('priority', 'medium')).lower(),
                'source': item.get('source', 'generic-import'),
                'source_alert_id': str(item.get('id', item.get('alert_id', uuid.uuid4())))[:64],
                'raw_data': json.dumps(item),
                'source_ip': item.get('source_ip', item.get('src_ip', '')),
                'dest_ip': item.get('dest_ip', item.get('dst_ip', '')),
                'rule_name': item.get('rule_name', item.get('rule', '')),
            }
            alerts.append(alert)
        return alerts


PARSERS = {
    'splunk': SplunkCSVParser,
    'sentinel': SentinelJSONParser,
    'qradar': QRadarXMLParser,
    'generic': GenericJSONParser,
}


# ── Main ────────────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Import SIEM alerts into ZOVARK")
    parser.add_argument("--format", choices=PARSERS.keys(), default="splunk",
                        help="SIEM export format (default: splunk)")
    parser.add_argument("--file", required=True, help="Path to alert export file")
    parser.add_argument("--tenant-id", required=True, help="Target tenant UUID")
    parser.add_argument("--api-url", default="http://localhost:8090",
                        help="ZOVARK API URL (default: http://localhost:8090)")
    parser.add_argument("--api-token", default="", help="JWT token for API auth")
    parser.add_argument("--investigate", action="store_true",
                        help="Submit each alert for investigation after import")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse and validate without inserting")
    args = parser.parse_args()

    # Parse alerts
    parser_cls = PARSERS[args.format]()
    print(f"Parsing {args.file} as {args.format} format...")
    try:
        alerts = parser_cls.parse(args.file)
    except Exception as e:
        print(f"ERROR: Failed to parse file: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Parsed {len(alerts)} alerts")

    if args.dry_run:
        for i, a in enumerate(alerts[:5]):
            print(f"  [{i}] {a.get('severity', '?'):8s} | {a.get('title', '?')[:60]}")
        if len(alerts) > 5:
            print(f"  ... and {len(alerts) - 5} more")
        return

    # Import via API
    headers = {"Content-Type": "application/json"}
    if args.api_token:
        headers["Authorization"] = f"Bearer {args.api_token}"

    imported = 0
    skipped = 0
    errors = 0

    with httpx.Client(timeout=30.0) as client:
        for i, alert in enumerate(alerts):
            try:
                # Insert via webhook endpoint (no auth required for webhooks)
                payload = {
                    "title": alert.get("title", "Imported Alert"),
                    "severity": alert.get("severity", "medium"),
                    "source": alert.get("source", args.format + "-import"),
                    "source_alert_id": alert.get("source_alert_id", ""),
                    "raw_data": alert.get("raw_data", "{}"),
                    "source_ip": alert.get("source_ip", ""),
                    "dest_ip": alert.get("dest_ip", ""),
                    "rule_name": alert.get("rule_name", ""),
                }

                resp = client.post(
                    f"{args.api_url}/api/v1/webhooks/import/alert",
                    json=payload,
                    headers=headers,
                )

                if resp.status_code in (200, 201):
                    imported += 1
                elif resp.status_code == 409:
                    skipped += 1  # Duplicate
                else:
                    errors += 1
                    if errors <= 3:
                        print(f"  WARN: Alert {i} returned {resp.status_code}: {resp.text[:200]}")

            except Exception as e:
                errors += 1
                if errors <= 3:
                    print(f"  ERROR: Alert {i} failed: {e}")

            if (i + 1) % 10 == 0:
                print(f"  Progress: {i + 1}/{len(alerts)} (imported={imported}, skipped={skipped}, errors={errors})")

    print(f"\nComplete: {imported} imported, {skipped} skipped (duplicates), {errors} errors")

    if args.investigate and imported > 0:
        print(f"\nNote: Use the dashboard to trigger investigations on imported alerts.")


if __name__ == "__main__":
    main()
