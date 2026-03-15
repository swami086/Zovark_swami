"""Zeek (Bro) network log ingestion and anomaly detection.

Parses Zeek TSV format, detects:
- Beaconing (periodic callbacks to C2)
- DNS tunneling (high-volume long queries)
- HTTP path traversal and command injection
- Large data transfers
"""
import json
import logging
import os
import re
import statistics
from collections import defaultdict
from typing import Dict, List, Optional

from temporalio import activity

logger = logging.getLogger(__name__)


def _parse_zeek_line(fields: List[str], header: List[str]) -> Dict:
    """Parse a single Zeek TSV line into a dict using the header."""
    if len(fields) != len(header):
        return {}
    record = {}
    for name, value in zip(header, fields):
        if value == "-" or value == "(empty)":
            record[name] = None
        else:
            record[name] = value
    return record


def _extract_zeek_fields(lines: List[str]) -> tuple:
    """Extract field names from Zeek header lines.

    Returns (field_names, data_start_index)
    """
    fields = []
    data_start = 0
    for i, line in enumerate(lines):
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]  # Skip "#fields" prefix
            data_start = i + 1
        elif line.startswith("#"):
            data_start = i + 1
        else:
            break
    return fields, data_start


def _decompress_if_needed(data: bytes, filename: str) -> str:
    """Decompress .zst files, return text content."""
    if filename.endswith(".zst"):
        try:
            import zstandard
            decompressor = zstandard.ZstdDecompressor()
            return decompressor.decompress(data).decode("utf-8", errors="replace")
        except ImportError:
            logger.warning("zstandard not installed, cannot decompress .zst files")
            return ""
    return data.decode("utf-8", errors="replace")


def detect_beaconing(records: List[Dict], std_dev_threshold: float = 0.1) -> List[Dict]:
    """Detect C2 beaconing patterns in conn.log records.

    Groups by source IP, computes inter-arrival times.
    Flags if std_dev < threshold * mean (regular intervals).
    """
    anomalies = []
    by_src = defaultdict(list)
    for r in records:
        src = r.get("id.orig_h")
        ts = r.get("ts")
        if src and ts:
            try:
                by_src[src].append(float(ts))
            except (ValueError, TypeError):
                pass

    for src_ip, timestamps in by_src.items():
        if len(timestamps) < 10:
            continue
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        if not intervals:
            continue
        mean_interval = statistics.mean(intervals)
        if mean_interval <= 0:
            continue
        std_interval = statistics.stdev(intervals) if len(intervals) > 1 else 0
        regularity = std_interval / mean_interval if mean_interval > 0 else 1.0

        if regularity < std_dev_threshold:
            anomalies.append({
                "type": "beaconing",
                "severity": "high",
                "source_ip": src_ip,
                "connection_count": len(timestamps),
                "mean_interval_sec": round(mean_interval, 2),
                "regularity_score": round(1.0 - regularity, 4),
                "description": f"Periodic beaconing detected: {src_ip} with {len(timestamps)} "
                               f"connections at ~{mean_interval:.1f}s intervals (regularity: {regularity:.4f})",
            })

    return anomalies


def detect_dns_tunneling(records: List[Dict], query_threshold: int = 100,
                          avg_length_threshold: int = 50) -> List[Dict]:
    """Detect DNS tunneling in dns.log records."""
    anomalies = []
    by_src = defaultdict(list)
    for r in records:
        src = r.get("id.orig_h")
        query = r.get("query")
        if src and query:
            by_src[src].append(query)

    for src_ip, queries in by_src.items():
        if len(queries) < query_threshold:
            continue
        avg_len = statistics.mean(len(q) for q in queries)
        if avg_len >= avg_length_threshold:
            anomalies.append({
                "type": "dns_tunneling",
                "severity": "critical",
                "source_ip": src_ip,
                "query_count": len(queries),
                "avg_query_length": round(avg_len, 1),
                "description": f"DNS tunneling suspected: {src_ip} sent {len(queries)} DNS queries "
                               f"with avg length {avg_len:.0f} chars",
            })

    return anomalies


def detect_http_suspicious(records: List[Dict]) -> List[Dict]:
    """Detect suspicious HTTP patterns (path traversal, command injection)."""
    suspicious_patterns = [
        (re.compile(r'\.\.[\\/]'), "path_traversal"),
        (re.compile(r'%2e%2e', re.I), "encoded_path_traversal"),
        (re.compile(r'[?&](?:cmd|exec|eval|system)=', re.I), "command_injection"),
        (re.compile(r'(?:powershell|cmd\.exe|/bin/(?:sh|bash))', re.I), "shell_access"),
    ]
    anomalies = []
    for r in records:
        uri = r.get("uri", "") or ""
        host = r.get("host", "") or ""
        src = r.get("id.orig_h", "unknown")
        for pattern, attack_type in suspicious_patterns:
            if pattern.search(uri):
                anomalies.append({
                    "type": f"http_{attack_type}",
                    "severity": "high",
                    "source_ip": src,
                    "host": host,
                    "uri": uri[:200],
                    "description": f"Suspicious HTTP: {attack_type} from {src} to {host}{uri[:100]}",
                })
    return anomalies


def detect_large_transfers(records: List[Dict], threshold_bytes: int = 100_000_000) -> List[Dict]:
    """Detect large data transfers in conn.log."""
    anomalies = []
    by_pair = defaultdict(int)
    for r in records:
        src = r.get("id.orig_h")
        dst = r.get("id.resp_h")
        orig_bytes = r.get("orig_bytes") or r.get("orig_ip_bytes") or "0"
        resp_bytes = r.get("resp_bytes") or r.get("resp_ip_bytes") or "0"
        try:
            total = int(orig_bytes) + int(resp_bytes)
            if src and dst:
                by_pair[(src, dst)] += total
        except (ValueError, TypeError):
            pass

    for (src, dst), total_bytes in by_pair.items():
        if total_bytes >= threshold_bytes:
            anomalies.append({
                "type": "large_transfer",
                "severity": "medium",
                "source_ip": src,
                "dest_ip": dst,
                "total_bytes": total_bytes,
                "total_mb": round(total_bytes / 1_000_000, 1),
                "description": f"Large transfer: {src} -> {dst}: {total_bytes / 1_000_000:.1f} MB",
            })

    return anomalies


@activity.defn
async def ingest_zeek_logs(params: dict) -> dict:
    """Temporal activity: ingest and analyze Zeek log batch.

    Args:
        params: {
            source_sensor: str,
            log_files: [{filename: str, content: str|bytes, log_type: str}],
            time_range: {start: str, end: str} (optional),
            tenant_id: str,
        }
    Returns:
        {records_processed, anomalies, iocs_extracted}
    """
    source_sensor = params.get("source_sensor", "unknown")
    log_files = params.get("log_files", [])
    tenant_id = params.get("tenant_id")

    all_anomalies = []
    all_iocs = set()
    total_records = 0

    for log_file in log_files:
        filename = log_file.get("filename", "")
        content = log_file.get("content", "")
        log_type = log_file.get("log_type", "")

        # Auto-detect log type from filename
        if not log_type:
            if "conn" in filename:
                log_type = "conn"
            elif "dns" in filename:
                log_type = "dns"
            elif "http" in filename:
                log_type = "http"
            else:
                log_type = "unknown"

        # Handle bytes or string content
        if isinstance(content, bytes):
            text = _decompress_if_needed(content, filename)
        else:
            text = content

        lines = text.strip().split("\n")
        fields, data_start = _extract_zeek_fields(lines)
        if not fields:
            continue

        records = []
        for line in lines[data_start:]:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split("\t")
            record = _parse_zeek_line(parts, fields)
            if record:
                records.append(record)

        total_records += len(records)

        # Detect anomalies based on log type
        if log_type == "conn":
            all_anomalies.extend(detect_beaconing(records))
            all_anomalies.extend(detect_large_transfers(records))
        elif log_type == "dns":
            all_anomalies.extend(detect_dns_tunneling(records))
        elif log_type == "http":
            all_anomalies.extend(detect_http_suspicious(records))

        # Extract IOCs
        for r in records:
            for field in ["id.orig_h", "id.resp_h", "query", "host"]:
                val = r.get(field)
                if val and val != "-":
                    all_iocs.add(val)

    return {
        "source_sensor": source_sensor,
        "records_processed": total_records,
        "anomalies": all_anomalies,
        "anomaly_count": len(all_anomalies),
        "iocs_extracted": list(all_iocs)[:500],
        "ioc_count": len(all_iocs),
    }
