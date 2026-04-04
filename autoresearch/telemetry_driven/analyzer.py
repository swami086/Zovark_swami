"""Weakness analyzer — turns telemetry into a ranked priority queue."""

from dataclasses import dataclass, field
from typing import List


BENIGN_TYPES = frozenset([
    "password_change", "windows_update", "health_check", "scheduled_backup",
    "vpn_login", "user_login", "benign-system-event", "benign_system_event",
    "service_restart", "group_policy_update", "certificate_renewal",
    "scheduled_task", "backup_job", "software_install", "antivirus_update",
    "disk_cleanup", "network_config", "dns_update", "dhcp_lease",
])


@dataclass
class Weakness:
    category: str       # scoring, detection, dedup, latency, coverage, error, infrastructure
    severity: str       # critical, high, medium, low
    task_type: str
    description: str
    metric_name: str
    metric_value: float
    threshold: float
    priority_score: float
    test_hints: List[str] = field(default_factory=list)

    def to_dict(self):
        return {
            "category": self.category, "severity": self.severity,
            "task_type": self.task_type, "description": self.description,
            "metric": f"{self.metric_name}={self.metric_value} (threshold={self.threshold})",
            "priority": self.priority_score, "test_hints": self.test_hints,
        }


class WeaknessAnalyzer:
    RISK_MIN_ATTACK = 65
    RISK_MAX_BENIGN = 25
    RISK_STDDEV_MAX = 15
    ERROR_RATE_MAX = 5
    DEDUP_RATIO_WARN = 95
    MITRE_MIN_PCT = 80
    LATENCY_P95_MAX = 30
    MANUAL_REVIEW_WARN = 20

    def __init__(self, snapshot: dict):
        self.data = snapshot.get("data", {})
        self.weaknesses: List[Weakness] = []

    def analyze(self) -> List[Weakness]:
        self.weaknesses = []
        self._check_risk_scores()
        self._check_verdicts()
        self._check_errors()
        self._check_dedup()
        self._check_latency()
        self._check_mitre()
        self._check_failures()
        self._check_health()
        self.weaknesses.sort(key=lambda w: w.priority_score, reverse=True)
        return self.weaknesses

    def _safe_float(self, v, default=0.0):
        try:
            return float(v) if v and v != "" else default
        except (ValueError, TypeError):
            return default

    def _safe_int(self, v, default=0):
        try:
            return int(float(v)) if v and v != "" else default
        except (ValueError, TypeError):
            return default

    def _check_risk_scores(self):
        for row in self.data.get("risk_scores", []):
            if len(row) < 6:
                continue
            tt, count, avg, std, mn, mx = row[0], self._safe_int(row[1]), self._safe_float(row[2]), self._safe_float(row[3]), self._safe_int(row[4]), self._safe_int(row[5])
            if tt in BENIGN_TYPES:
                if avg > self.RISK_MAX_BENIGN:
                    self.weaknesses.append(Weakness("scoring", "high", tt,
                        f"Benign '{tt}' avg risk {avg} (should be <={self.RISK_MAX_BENIGN})",
                        "avg_risk_benign", avg, self.RISK_MAX_BENIGN, 80,
                        [f"Submit 3 {tt} variants", "Check signal boost inflation"]))
                continue
            if avg < self.RISK_MIN_ATTACK and count >= 2:
                gap = self.RISK_MIN_ATTACK - avg
                self.weaknesses.append(Weakness("scoring",
                    "critical" if avg < 40 else "high", tt,
                    f"Attack '{tt}' avg risk {avg} (need >={self.RISK_MIN_ATTACK})",
                    "avg_risk_attack", avg, self.RISK_MIN_ATTACK, min(95, 50 + gap),
                    [f"Submit 3 strong {tt} alerts", f"Check detect_{tt} risk weights"]))
            if std > self.RISK_STDDEV_MAX and count >= 3:
                self.weaknesses.append(Weakness("scoring", "medium", tt,
                    f"'{tt}' inconsistent scoring (stddev={std})",
                    "risk_stddev", std, self.RISK_STDDEV_MAX, 40 + std,
                    [f"Submit 5 {tt} alerts with varying strength"]))

    def _check_verdicts(self):
        by_type = {}
        for row in self.data.get("verdicts", []):
            if len(row) < 3:
                continue
            tt, v, c = row[0], row[1], self._safe_int(row[2])
            by_type.setdefault(tt, {})[v] = c
        for tt, verdicts in by_type.items():
            total = sum(verdicts.values())
            manual = verdicts.get("needs_manual_review", 0)
            if total >= 3 and 100 * manual / total > self.MANUAL_REVIEW_WARN:
                self.weaknesses.append(Weakness("detection", "high", tt,
                    f"'{tt}': {manual}/{total} need manual review",
                    "manual_review_pct", 100 * manual / total, self.MANUAL_REVIEW_WARN,
                    60 + manual / total * 30,
                    [f"Submit {tt} with unambiguous attack indicators"]))

    def _check_errors(self):
        for row in self.data.get("error_rates", []):
            if len(row) < 5:
                continue
            tt, errs, _, total, pct = row[0], self._safe_int(row[1]), row[2], self._safe_int(row[3]), self._safe_float(row[4])
            if pct > self.ERROR_RATE_MAX:
                self.weaknesses.append(Weakness("error",
                    "critical" if pct > 20 else "high", tt,
                    f"'{tt}': {pct}% error rate ({errs}/{total})",
                    "error_rate_pct", pct, self.ERROR_RATE_MAX, min(100, 70 + pct),
                    [f"Replay recent failed {tt} investigations"]))

    def _check_dedup(self):
        stats = self.data.get("dedup_stats", {})
        ratio = stats.get("dedup_ratio_pct", 0)
        if ratio > self.DEDUP_RATIO_WARN:
            self.weaknesses.append(Weakness("dedup", "medium", "*",
                f"Dedup ratio {ratio}% — possibly too aggressive",
                "dedup_ratio_pct", ratio, self.DEDUP_RATIO_WARN, 45,
                ["Verify severity escalation bypass", "Review TTL values"]))

    def _check_latency(self):
        for row in self.data.get("latency", []):
            if len(row) < 6:
                continue
            path, cnt, avg, p50, p95, mx = row[0], self._safe_int(row[1]), self._safe_float(row[2]), self._safe_float(row[3]), self._safe_float(row[4]), self._safe_int(row[5])
            if p95 > self.LATENCY_P95_MAX:
                self.weaknesses.append(Weakness("latency",
                    "high" if p95 > 60 else "medium", f"path:{path}",
                    f"Path '{path}': P95={p95}s (max={mx}s)",
                    "latency_p95_sec", p95, self.LATENCY_P95_MAX, min(80, 30 + p95),
                    [f"Check if LLM or tool execution is bottleneck"]))

    def _check_mitre(self):
        for row in self.data.get("mitre_coverage", []):
            if len(row) < 4:
                continue
            tt, total, _, pct = row[0], self._safe_int(row[1]), row[2], self._safe_float(row[3])
            if pct < self.MITRE_MIN_PCT and total >= 2:
                self.weaknesses.append(Weakness("coverage", "medium", tt,
                    f"'{tt}': only {pct}% have MITRE mappings",
                    "mitre_coverage_pct", pct, self.MITRE_MIN_PCT, 30,
                    [f"Check map_mitre in {tt} plan"]))

    def _check_failures(self):
        types = {}
        for row in self.data.get("recent_failures", []):
            if len(row) >= 2:
                types[row[1]] = types.get(row[1], 0) + 1
        for tt, c in types.items():
            if c >= 3:
                self.weaknesses.append(Weakness("error", "high", tt,
                    f"'{tt}': {c} recent failures — systematic issue",
                    "recent_failure_count", c, 2, 75,
                    [f"Check worker logs for {tt} errors"]))

    def _check_health(self):
        health = self.data.get("system_health", {})
        for svc in ["postgres", "redis", "temporal", "inference"]:
            st = health.get(svc)
            if st and st != "ok":
                self.weaknesses.append(Weakness("infrastructure", "critical", "*",
                    f"Service '{svc}' is {st}", f"health_{svc}", 0, 1, 100,
                    ["Fix infrastructure before testing"]))

    def summary(self) -> str:
        if not self.weaknesses:
            return "No weaknesses found. System is healthy."
        lines = [f"Found {len(self.weaknesses)} weaknesses:", ""]
        for i, w in enumerate(self.weaknesses, 1):
            lines.append(f"  {i}. [{w.severity.upper()}] {w.description}")
            lines.append(f"     Priority: {w.priority_score:.0f}/100 | Category: {w.category}")
            if w.test_hints:
                lines.append(f"     Test: {w.test_hints[0]}")
            lines.append("")
        return "\n".join(lines)

    def to_json(self):
        return [w.to_dict() for w in self.weaknesses]
