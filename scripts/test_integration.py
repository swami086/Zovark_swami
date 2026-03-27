import os
import time
import requests
import json

API_BASE = os.environ.get("ZOVARC_API_URL", "http://localhost:8090/api/v1")
DB_URI = os.environ.get("DATABASE_URL", "postgresql://zovarc:zovarc_dev_2026@localhost:5432/zovarc")

def get_db_output(task_id):
    import psycopg2
    try:
        conn = psycopg2.connect(DB_URI)
        cur = conn.cursor()
        cur.execute("SELECT output FROM agent_tasks WHERE id = %s", (task_id,))
        row = cur.fetchone()
        conn.close()
        if row and row[0]:
            return row[0]
    except Exception as e:
        print(f"DB Error: {e}")
    return {}


def main():
    print("Starting Integration Test: API -> Worker -> DB")

    try:
        # 1. Login
        print(f"Logging in to {API_BASE}/auth/login...")
        login_resp = requests.post(f"{API_BASE}/auth/login", json={
            "email": "admin@testcorp.com",
            "password": "password123"
        }, timeout=10)
        login_resp.raise_for_status()
        token = login_resp.json().get("token")
        if not token:
            print("FAILED: No token received in login response")
            return
        print("Successfully authenticated.")

        headers = {"Authorization": f"Bearer {token}"}
        
        # 2. Test each skill
        skills = ["brute_force", "ransomware", "lateral_movement", "c2", "phishing"]
        skill_map = {
            "brute_force": "Brute Force Investigation",
            "ransomware": "Ransomware Triage",
            "lateral_movement": "Lateral Movement Detection",
            "c2": "C2 Communication Hunt",
            "phishing": "Phishing Investigation"
        }
        results = {}

        for skill in skills:
            print(f"\n--- Testing Skill: {skill} ---")
            
            # Read easy.log from the host filesystem
            log_path = os.path.join(os.path.dirname(__file__), "..", "tests", "corpus", skill, "easy.log")
            if not os.path.exists(log_path):
                # Fallback to hardcoded absolute path
                log_path = f"C:\\Users\\vinay\\Desktop\\ZOVARC\\zovarc-mvp\\tests\\corpus\\{skill}\\easy.log"
                if not os.path.exists(log_path):
                    print(f"SKIPPED {skill}: {log_path} not found")
                    results[skill] = "Skipped (No Log)"
                    continue
                
            with open(log_path, "r", encoding="utf-8") as f:
                log_data = f.read()

            # Create Task
            task_payload = {
                "task_type": skill_map[skill],
                "input": {
                    "prompt": f"Analyze this log for {skill} activity.",
                    "log_data": log_data,
                    "filename": f"easy.log"
                }
            }
            
            print(f"Submitting task to {API_BASE}/tasks...")
            create_resp = requests.post(f"{API_BASE}/tasks", headers=headers, json=task_payload)
            if create_resp.status_code != 202:
                print(f"FAILED to create task for {skill}: {create_resp.status_code} - {create_resp.text}")
                results[skill] = "Failed (Creation)"
                continue
                
            task_id = create_resp.json().get("task_id")
            print(f"Task created with ID: {task_id}. Polling for completion...")

            # 3. Poll for completion
            passed = False
            for i in range(24): # 120s timeout (24 * 5s)
                time.sleep(5)
                get_resp = requests.get(f"{API_BASE}/tasks/{task_id}", headers=headers)
                if get_resp.status_code != 200:
                    print(f"  Error polling task: {get_resp.status_code}")
                    continue
                    
                task_data = get_resp.json()
                status = task_data.get("status")
                print(f"  Status: {status}")
                
                if status == "completed":
                    db_output = get_db_output(task_id)
                    stdout_str = db_output.get("stdout", "{}")
                    try:
                        parsed_stdout = json.loads(stdout_str)
                    except Exception:
                        parsed_stdout = {}
                        
                    findings = parsed_stdout.get("findings", [])
                    risk_score = parsed_stdout.get("risk_score", 0)
                    
                    if findings and len(findings) > 0:
                        if risk_score > 0:
                            print(f"  SUCCESS! Found findings with risk_score={risk_score}.")
                            results[skill] = "Passed"
                        else:
                            print(f"  FAILED! Task completed and found {len(findings)} findings but risk score is 0.")
                            results[skill] = "Failed (No Risk)"
                        passed = True
                    else:
                        print("  FAILED! Task completed but no findings generated.")
                        results[skill] = "Failed (No Findings)"
                        passed = True # completed but failed
                    break
                elif status == "awaiting_approval":
                    # Step 1 completed but follow-up needs approval — check step 1 results
                    import psycopg2 as _pg
                    _conn = _pg.connect(DB_URI)
                    _cur = _conn.cursor()
                    _cur.execute("SELECT output::text FROM investigation_steps WHERE task_id = %s AND step_number = 1 AND status = 'completed'", (task_id,))
                    _row = _cur.fetchone()
                    _conn.close()
                    if _row and _row[0]:
                        try:
                            step1_out = json.loads(json.loads(_row[0])) if isinstance(_row[0], str) and _row[0].startswith('"') else json.loads(_row[0])
                        except Exception:
                            try:
                                step1_out = json.loads(_row[0])
                            except Exception:
                                step1_out = {}
                        step1_findings = step1_out.get("findings", [])
                        step1_risk = step1_out.get("risk_score", 0)
                        if step1_findings and step1_risk > 0:
                            print(f"  SUCCESS! Step 1 completed with risk_score={step1_risk} (awaiting approval for follow-up).")
                            results[skill] = "Passed"
                            passed = True
                            break
                    print(f"  AWAITING APPROVAL (step 1 not verified).")
                    continue
                elif status == "failed":
                    print("  FAILED! Task execution failed.")
                    results[skill] = "Failed (Execution)"
                    passed = True
                    break
            
            if not passed:
                print(f"  TIMEOUT! Task did not complete in 120s.")
                results[skill] = "Failed (Timeout)"
                
        # 5. Print Summary
        print("\n=== INTEGRATION TEST SUMMARY ===")
        all_passed = True
        for skill, result in results.items():
            print(f"{skill.ljust(20)} : {result}")
            if result != "Passed":
                all_passed = False
                
        if all_passed:
            print("\nRESULT: ALL PASS")
        else:
            print("\nRESULT: SOME FAILURES")
            
    except Exception as e:
        print(f"Unexpected error during integration test: {e}")

if __name__ == "__main__":
    main()
