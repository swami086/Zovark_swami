"""Test generator — creates targeted alerts from identified weaknesses."""

import hashlib
import json
import os
import random
from pathlib import Path
from typing import Dict, List

from analyzer import Weakness


def _investigation_plans_path() -> Path:
    override = os.environ.get("ZOVARK_INVESTIGATION_PLANS_PATH", "").strip()
    if override:
        return Path(override)
    here = Path(__file__).resolve().parent
    return here.parents[2] / "worker" / "tools" / "investigation_plans.json"


def _load_alert_templates_from_plans() -> Dict[str, List[dict]]:
    """Build synthetic SIEM templates from worker/tools/investigation_plans.json keys.

    New plan entries are picked up at runtime without editing this module.
    """
    path = _investigation_plans_path()
    if not path.is_file():
        return {}

    try:
        with open(path, encoding="utf-8") as f:
            plans = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}

    out: Dict[str, List[dict]] = {}
    for plan_key, spec in plans.items():
        if not isinstance(spec, dict):
            continue
        desc = str(spec.get("description", plan_key))[:800]
        out[plan_key] = [
            {
                "severity": "high",
                "source_ip": "10.0.1.{r}",
                "rule_name": plan_key.replace("_", " ").title(),
                "raw_log": (
                    f"{desc} | correlation test event | brute phishing malware "
                    f"beacon lateral movement exfiltration | host WS-{{r}} | src 10.0.1.{{r}}"
                ),
            }
        ]
    return out


# Loaded at import and on each TestGenerator instance build (fresh file edits in dev)
ALERT_TEMPLATES: Dict[str, List[dict]] = _load_alert_templates_from_plans()

BENIGN_TEMPLATES = {
    "password_change": {"severity": "info", "raw_log": "User jdoe changed password successfully via self-service portal"},
    "windows_update": {"severity": "info", "raw_log": "Windows Update KB5034441 installed successfully on WORKSTATION-01"},
    "health_check": {"severity": "info", "raw_log": "System health check passed. CPU 45 percent Memory 62 percent. All services normal."},
    "scheduled_backup": {"severity": "info", "raw_log": "Nightly backup completed successfully. 150 GB backed up."},
    "user_login": {"severity": "info", "raw_log": "User asmith logged in via RDP from 10.0.1.150 at 09:00 UTC"},
}


class TestGenerator:
    def __init__(self, weaknesses: List[Weakness]):
        self.weaknesses = weaknesses
        self._templates = _load_alert_templates_from_plans() or ALERT_TEMPLATES

    def generate(self, max_tests=30) -> List[Dict]:
        tests = []
        seen_types = set()
        for w in self.weaknesses:
            if len(tests) >= max_tests - len(BENIGN_TEMPLATES):
                break
            generated = self._for_weakness(w)
            for t in generated:
                if t["task_type"] not in seen_types or len(tests) < 5:
                    tests.append(t)
                    seen_types.add(t["task_type"])
        tests.extend(self._benign_baseline())
        return tests[:max_tests]

    def _for_weakness(self, w: Weakness) -> List[Dict]:
        tt = w.task_type
        if tt == "*" or tt.startswith("path:"):
            return self._diverse(2)
        templates = self._templates.get(tt, [])
        if not templates:
            return [self._generic(tt, w)]
        return [self._fill(tt, t, w) for t in templates[:2]]

    def _fill(self, task_type, template, weakness):
        r = random.randint(1, 254)
        r2 = random.randint(1, 254)
        c = random.choice([100, 250, 500])
        siem = {}
        for k, v in template.items():
            if isinstance(v, str):
                v = v.replace("{r}", str(r)).replace("{r2}", str(r2)).replace("{c}", str(c))
            siem[k] = v
        siem.setdefault("title", siem.get("rule_name", task_type))
        return {
            "name": f"{task_type}_{hashlib.md5(str(siem).encode()).hexdigest()[:6]}",
            "task_type": task_type,
            "input": {
                "prompt": f"AutoResearch test: {weakness.description[:80]}",
                "severity": siem.pop("severity", "high"),
                "siem_event": siem
            },
            "expect": "attack", "min_risk": 65,
            "weakness_ref": weakness.description[:100],
        }

    def _benign_baseline(self):
        alerts = []
        for tt, tpl in BENIGN_TEMPLATES.items():
            alerts.append({
                "name": f"benign_{tt}",
                "task_type": tt,
                "input": {
                    "prompt": f"Benign baseline: {tt}",
                    "severity": tpl["severity"],
                    "siem_event": {
                        "title": tt.replace("_", " ").title(),
                        "rule_name": tt,
                        "raw_log": tpl["raw_log"],
                        "hostname": f"BASELINE-{random.randint(1,99):02d}",
                    }
                },
                "expect": "benign", "max_risk": 25,
                "weakness_ref": "baseline regression",
            })
        return alerts

    def _diverse(self, count):
        keys = list(self._templates.keys())
        if not keys:
            return []
        random.shuffle(keys)
        out = []
        dummy = Weakness(
            category="diverse",
            severity="medium",
            task_type="diverse",
            description="diverse sample",
            metric_name="n/a",
            metric_value=0.0,
            threshold=0.0,
            priority_score=0.0,
        )
        for t in keys[:count]:
            tpl = random.choice(self._templates[t])
            out.append(self._fill(t, tpl, dummy))
        return out

    def _generic(self, task_type, weakness):
        r = random.randint(1, 254)
        return {
            "name": f"generic_{task_type}",
            "task_type": task_type,
            "input": {
                "prompt": f"Generic test: {task_type}",
                "severity": "high",
                "siem_event": {
                    "title": f"Test: {task_type}",
                    "source_ip": f"10.0.1.{r}",
                    "rule_name": f"AutoTest-{task_type}",
                    "raw_log": f"Auto-generated for {task_type} from 10.0.1.{r} suspicious activity",
                }
            },
            "expect": "attack", "min_risk": 50,
            "weakness_ref": weakness.description[:100],
        }
