#!/usr/bin/env python3
"""
Telemetry-Driven AutoResearch Cycle Runner.

Usage: python3 run_cycle.py [--hours 168] [--max-tests 20] [--wait 120] [--dry-run]
"""

import argparse
import json
import os
import sys
import time

from collector import TelemetrySnapshot
from analyzer import WeaknessAnalyzer
from generator import TestGenerator
from runner import TestRunner
from delta import DeltaAnalyzer


def main():
    parser = argparse.ArgumentParser(description="Run telemetry-driven AutoResearch cycle")
    parser.add_argument("--hours", type=int, default=168)
    parser.add_argument("--max-tests", type=int, default=20)
    parser.add_argument("--wait", type=int, default=120)
    parser.add_argument("--output", default="/app/autoresearch_td/results")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")

    # Phase 0: Collect
    print("=" * 70)
    print("  PHASE 0: COLLECTING TELEMETRY")
    print("=" * 70)
    collector = TelemetrySnapshot()
    snapshot = collector.collect(hours=args.hours)
    snap_path = os.path.join(args.output, f"snapshot_{ts}.json")
    collector.save(snapshot, snap_path)
    print(f"  Sources: {snapshot['sources']}")
    if snapshot["sources"].get("postgres") != "ok":
        print("FATAL: PostgreSQL unavailable")
        return 1

    # Phase 1: Analyze
    print("\n" + "=" * 70)
    print("  PHASE 1: ANALYZING WEAKNESSES")
    print("=" * 70)
    analyzer = WeaknessAnalyzer(snapshot)
    weaknesses = analyzer.analyze()
    print(analyzer.summary())
    with open(os.path.join(args.output, f"weaknesses_{ts}.json"), "w") as f:
        json.dump(analyzer.to_json(), f, indent=2)

    # Phase 2: Generate
    print("=" * 70)
    print("  PHASE 2: GENERATING TESTS")
    print("=" * 70)
    tests = TestGenerator(weaknesses).generate(max_tests=args.max_tests)
    attacks = [t for t in tests if t["expect"] == "attack"]
    benign = [t for t in tests if t["expect"] == "benign"]
    print(f"  Generated: {len(tests)} tests ({len(attacks)} attack, {len(benign)} benign)")
    tests_path = os.path.join(args.output, f"tests_{ts}.json")
    with open(tests_path, "w") as f:
        json.dump(tests, f, indent=2, default=str)

    if args.dry_run:
        print(f"\n  DRY RUN complete. Tests saved to {tests_path}")
        return 0

    # Phase 3: Run
    print("\n" + "=" * 70)
    print("  PHASE 3: RUNNING TESTS")
    print("=" * 70)
    runner = TestRunner()
    results = runner.run(tests, wait_seconds=args.wait)
    with open(os.path.join(args.output, f"results_{ts}.json"), "w") as f:
        json.dump(results, f, indent=2, default=str)

    # Phase 4: Delta
    print("\n" + "=" * 70)
    print("  PHASE 4: ANALYZING RESULTS")
    print("=" * 70)
    delta = DeltaAnalyzer(snapshot, results, weaknesses)
    report = delta.analyze()
    delta.print_report(report)
    with open(os.path.join(args.output, f"report_{ts}.json"), "w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n  Files saved to {args.output}/")
    s = report["summary"]
    if s["detection_rate"] >= 0.9 and s["fp_rate"] <= 0.1:
        print(f"  EXIT: 0 (PASSED — detection={100*s['detection_rate']:.0f}% FP={100*s['fp_rate']:.0f}%)")
        return 0
    else:
        print(f"  EXIT: 1 (NEEDS WORK — detection={100*s['detection_rate']:.0f}% FP={100*s['fp_rate']:.0f}%)")
        return 1


if __name__ == "__main__":
    sys.exit(main())
