"""Delta analyzer — compares test results against baseline telemetry."""

import json
from typing import List, Dict
from analyzer import Weakness


class DeltaAnalyzer:
    def __init__(self, baseline: dict, results: List[Dict], weaknesses: List[Weakness]):
        self.baseline = baseline
        self.results = results
        self.weaknesses = weaknesses

    def analyze(self) -> Dict:
        attacks = [r for r in self.results if r["test"]["expect"] == "attack"]
        benign = [r for r in self.results if r["test"]["expect"] == "benign"]

        ap = sum(1 for r in attacks if r.get("passed"))
        at = len(attacks)
        risks = [r["risk_score"] for r in attacks if (r.get("risk_score") or -1) >= 0]

        bp = sum(1 for r in benign if r.get("passed"))
        bt = len(benign)

        report = {
            "summary": {
                "detection_rate": ap / max(at, 1),
                "attack_passed": ap, "attack_count": at,
                "risk_mean": sum(risks) / max(len(risks), 1) if risks else 0,
                "risk_min": min(risks) if risks else 0,
                "risk_max": max(risks) if risks else 0,
                "fp_rate": 1 - bp / max(bt, 1),
                "benign_passed": bp, "benign_count": bt,
            },
            "attack_results": [],
            "benign_results": [],
            "improvements": [],
            "regressions": [],
            "next_priorities": [],
        }

        # Baseline risk by type
        base_risks = {}
        for row in self.baseline.get("data", {}).get("risk_scores", []):
            if len(row) >= 3:
                try: base_risks[row[0]] = float(row[2])
                except: pass

        for r in attacks:
            tt = r["test"]["task_type"]
            risk = r.get("risk_score", 0) or 0
            report["attack_results"].append({
                "name": r["test"]["name"], "task_type": tt,
                "verdict": r.get("verdict"), "risk": risk,
                "passed": r.get("passed"),
            })
            br = base_risks.get(tt)
            if br is not None:
                d = risk - br
                if d > 10:
                    report["improvements"].append(f"{tt}: {br:.0f} -> {risk} (+{d:.0f})")
                elif d < -10:
                    report["regressions"].append(f"{tt}: {br:.0f} -> {risk} ({d:.0f}) REGRESSION")

        for r in benign:
            report["benign_results"].append({
                "name": r["test"]["name"], "task_type": r["test"]["task_type"],
                "verdict": r.get("verdict"), "risk": r.get("risk_score"),
                "passed": r.get("passed"),
            })

        for r in attacks:
            if not r.get("passed"):
                report["next_priorities"].append({
                    "task_type": r["test"]["task_type"],
                    "verdict": r.get("verdict"), "risk": r.get("risk_score"),
                    "action": f"Fix {r['test']['task_type']}: verdict={r.get('verdict')} risk={r.get('risk_score')}",
                })
        for r in benign:
            if not r.get("passed"):
                report["next_priorities"].append({
                    "task_type": r["test"]["task_type"],
                    "verdict": r.get("verdict"), "risk": r.get("risk_score"),
                    "action": f"Fix FP: {r['test']['task_type']} verdict={r.get('verdict')} risk={r.get('risk_score')}",
                })
        return report

    def print_report(self, report: Dict):
        s = report["summary"]
        print("\n" + "=" * 70)
        print("  TELEMETRY-DRIVEN AUTORESEARCH — CYCLE REPORT")
        print("=" * 70)
        print(f"\n  Detection: {s['attack_passed']}/{s['attack_count']} = {100*s['detection_rate']:.0f}%")
        print(f"  FP rate:   {s['benign_count']-s['benign_passed']}/{s['benign_count']} = {100*s['fp_rate']:.0f}%")
        print(f"  Risk:      mean={s['risk_mean']:.0f} min={s['risk_min']} max={s['risk_max']}")

        print("\n  ATTACK RESULTS:")
        for r in report["attack_results"]:
            mark = "+" if r["passed"] else "x"
            print(f"    {mark} {r['task_type']:25s} verdict={str(r['verdict']):20s} risk={r['risk']}")
        print("\n  BENIGN RESULTS:")
        for r in report["benign_results"]:
            mark = "+" if r["passed"] else "x"
            print(f"    {mark} {r['task_type']:25s} verdict={str(r['verdict']):20s} risk={r['risk']}")

        if report["improvements"]:
            print("\n  IMPROVEMENTS:")
            for i in report["improvements"]:
                print(f"    ^ {i}")
        if report["regressions"]:
            print("\n  REGRESSIONS:")
            for r in report["regressions"]:
                print(f"    v {r}")
        if report["next_priorities"]:
            print("\n  NEXT PRIORITIES:")
            for p in report["next_priorities"]:
                print(f"    > {p['action']}")

        print("\n" + "=" * 70)
        if s["detection_rate"] >= 0.9 and s["fp_rate"] <= 0.1:
            print("  CYCLE STATUS: PASSED")
        else:
            print("  CYCLE STATUS: NEEDS WORK")
        print("=" * 70)
