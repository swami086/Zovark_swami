import os
import json
import subprocess
import psycopg2
import sys
from concurrent.futures import ThreadPoolExecutor

BASE_DIR = os.environ.get("CORPUS_DIR", "/app/tests/corpus")
RESULTS_DIR = os.environ.get("RESULTS_DIR", "/app/tests/results")

SKILL_MAPPING = {
    "brute_force": "brute-force-investigation",
    "ransomware": "ransomware-triage",
    "lateral_movement": "lateral-movement-detection",
    "c2": "c2-communication-hunt",
    "phishing": "phishing-investigation"
}

def get_db_connection():
    return psycopg2.connect(
        host=os.environ.get("POSTGRES_HOST", "hydra-postgres"),
        port=5432,
        dbname="hydra",
        user="hydra",
        password=os.environ.get("POSTGRES_PASSWORD", "hydra_dev_2026")
    )

def fetch_skill_data(skill_slug):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT code_template, parameters FROM agent_skills WHERE skill_slug = %s", (skill_slug,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    if row:
        return row[0], row[1]
    return None, None

def render_template(template_str, log_data, parameters):
    rendered = template_str.replace("{{log_data}}", json.dumps(log_data))
    for param_def in parameters:
        name = param_def.get("name")
        if name != "log_data":
            default_val = param_def.get("default")
            # JSON dump the default value to encode it correctly in python code
            val_str = json.dumps(default_val)
            rendered = rendered.replace("{{" + name + "}}", val_str)
    return rendered

def check_keywords(findings, recommendations, keywords):
    text_to_check = " ".join([f.get("title", "") for f in findings]).lower()
    text_to_check += " " + " ".join([r for r in recommendations]).lower()
    for kw in keywords:
        if kw.lower() in text_to_check:
            return True
    return False if keywords else True

def run_test_case(skill_dir, skill_slug, log_file, expected_file, template, parameters):
    with open(log_file, "r") as f:
        log_data_str = f.read()
        log_data_str = log_data_str.replace('\\', '\\\\')
    with open(expected_file, "r") as f:
        expected = json.load(f)

    script_content = render_template(template, log_data_str, parameters)
    temp_script = f"/tmp/test_{skill_dir}_{os.path.basename(log_file)}.py"
    try:
        with open(temp_script, "w") as f:
            f.write(script_content)

        result = subprocess.run(
            ["python", temp_script],
            capture_output=True,
            text=True,
            timeout=60
        )

        output_json = None
        no_crash = False
        if result.returncode == 0:
            try:
                output_json = json.loads(result.stdout.strip())
                no_crash = True
            except json.JSONDecodeError:
                pass

        metrics = {
            "test_case": f"{skill_dir}/{os.path.basename(log_file)}",
            "no_crash": no_crash,
            "finding_count_pass": False,
            "risk_score_pass": False,
            "iocs_pass": False,
            "keywords_pass": False,
            "overall_pass": False,
            "error": result.stderr if not no_crash else ""
        }

        if no_crash and output_json:
            findings = output_json.get("findings", [])
            risk_score = output_json.get("risk_score", 0)
            iocs = output_json.get("iocs", {}).get("ips", [])
            recommendations = output_json.get("recommendations", [])

            f_count_range = expected.get("expected_finding_count_range", [0, 999])
            if f_count_range[0] <= len(findings) <= f_count_range[1]:
                metrics["finding_count_pass"] = True

            r_score_range = expected.get("expected_risk_score_range", [0, 100])
            if r_score_range[0] <= risk_score <= r_score_range[1]:
                metrics["risk_score_pass"] = True

            expected_ips = expected.get("expected_iocs", {}).get("ips", [])
            if all(ip in iocs for ip in expected_ips): # and len(iocs) >= expected.get("expected_iocs", {}).get("min_ip_count", 0):
                metrics["iocs_pass"] = True

            keywords = expected.get("must_contain_keywords", [])
            if check_keywords(findings, recommendations, keywords):
                metrics["keywords_pass"] = True

            if metrics["finding_count_pass"] and metrics["risk_score_pass"] and metrics["iocs_pass"] and metrics["keywords_pass"]:
                metrics["overall_pass"] = True

        return metrics
    except subprocess.TimeoutExpired:
        return {
            "test_case": f"{skill_dir}/{os.path.basename(log_file)}",
            "no_crash": False,
            "finding_count_pass": False,
            "risk_score_pass": False,
            "iocs_pass": False,
            "keywords_pass": False,
            "overall_pass": False,
            "error": "Timeout"
        }
    finally:
        if os.path.exists(temp_script):
            os.remove(temp_script)

def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    all_results = []

    print(f"{'Test Case':<35} | {'Crash':<5} | {'Finds':<5} | {'Risk':<5} | {'IOCs':<5} | {'Keyws':<5} | {'Overall':<7}")
    print("-" * 85)

    for skill_dir, skill_slug in SKILL_MAPPING.items():
        dir_path = os.path.join(BASE_DIR, skill_dir)
        if not os.path.isdir(dir_path):
            print(f"Directory missing: {dir_path}")
            continue

        template, parameters = fetch_skill_data(skill_slug)
        if not template:
            print(f"Template missing in DB for: {skill_slug}")
            continue

        logs = [f for f in os.listdir(dir_path) if f.endswith(".log")]
        for log_f in sorted(logs):
            base_name = log_f.replace(".log", "")
            expected_json = os.path.join(dir_path, f"{base_name}.expected.json")
            log_path = os.path.join(dir_path, log_f)

            if os.path.exists(expected_json):
                metrics = run_test_case(skill_dir, skill_slug, log_path, expected_json, template, parameters)
                all_results.append(metrics)

                print(f"{metrics['test_case']:<35} | "
                      f"{'PASS' if metrics['no_crash'] else 'FAIL':<5} | "
                      f"{'PASS' if metrics['finding_count_pass'] else 'FAIL':<5} | "
                      f"{'PASS' if metrics['risk_score_pass'] else 'FAIL':<5} | "
                      f"{'PASS' if metrics['iocs_pass'] else 'FAIL':<5} | "
                      f"{'PASS' if metrics['keywords_pass'] else 'FAIL':<5} | "
                      f"{'PASS' if metrics['overall_pass'] else 'FAIL':<7}")

    with open(os.path.join(RESULTS_DIR, "benchmark_results.json"), "w") as f:
        json.dump(all_results, f, indent=2)

    with open(os.path.join(RESULTS_DIR, "BENCHMARK.md"), "w") as f:
        f.write("# Sprint 12 Phase 1 Benchmark Results\n\n")
        f.write("## Summary\n")
        total = len(all_results)
        passed = sum(1 for r in all_results if r["overall_pass"])
        f.write(f"Total Tests: {total}\n")
        f.write(f"Passed: {passed}\n")
        f.write(f"Failed: {total - passed}\n\n")

        f.write("## Detailed Results\n")
        f.write("| Test Case | No Crash | Findings OK | Risk Score OK | IOCs OK | Keywords OK | Overall |\n")
        f.write("| --- | --- | --- | --- | --- | --- | --- |\n")
        for r in all_results:
            f.write(f"| {r['test_case']} | "
                    f"{'✅' if r['no_crash'] else '❌'} | "
                    f"{'✅' if r['finding_count_pass'] else '❌'} | "
                    f"{'✅' if r['risk_score_pass'] else '❌'} | "
                    f"{'✅' if r['iocs_pass'] else '❌'} | "
                    f"{'✅' if r['keywords_pass'] else '❌'} | "
                    f"{'✅' if r['overall_pass'] else '❌'} |\n")

if __name__ == "__main__":
    main()
