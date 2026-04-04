#!/usr/bin/env python3
"""
Red Team Evaluation Harness — tests attack vectors against the live system.
Generates bypasses/ directory entries for any vector that evades detection.
"""
import json
import asyncio
import httpx
import sys
import os
from datetime import datetime

API_URL = "http://localhost:8090"
ADMIN_EMAIL = "admin@test.local"
ADMIN_PASS = "TestPass2026"

async def get_token(client: httpx.AsyncClient) -> str:
    """Get auth token."""
    r = await client.post(
        f"{API_URL}/api/v1/auth/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASS}
    )
    r.raise_for_status()
    return r.json()["token"]

async def submit_investigation(client: httpx.AsyncClient, token: str, vector: dict) -> dict:
    """Submit a single attack vector as an investigation."""
    task_type = vector.get("task_type", "generic")
    siem_event = vector.get("siem_event", {})
    
    payload = {
        "task_type": task_type,
        "input": {
            "prompt": vector.get("name", "Red team test"),
            "severity": "high",
            "siem_event": siem_event
        }
    }
    
    r = await client.post(
        f"{API_URL}/api/v1/tasks",
        headers={"Authorization": f"Bearer {token}"},
        json=payload
    )
    r.raise_for_status()
    return r.json()

async def poll_result(client: httpx.AsyncClient, token: str, task_id: str, max_wait: int = 120) -> dict:
    """Poll for investigation result."""
    for _ in range(max_wait // 5):
        await asyncio.sleep(5)
        r = await client.get(
            f"{API_URL}/api/v1/tasks/{task_id}",
            headers={"Authorization": f"Bearer {token}"}
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") in ["completed", "error"]:
                return data
    return {"status": "timeout", "task_id": task_id}

def evaluate_result(vector: dict, result: dict) -> dict:
    """Evaluate if the vector was detected correctly."""
    expected_verdict = vector.get("expected_verdict")
    expected_risk_min = vector.get("expected_risk_min", 0)
    
    output = result.get("output", {})
    actual_verdict = output.get("verdict", "unknown")
    actual_risk = output.get("risk_score", 0)
    
    # Check verdict match
    verdict_match = actual_verdict == expected_verdict
    
    # Check risk score minimum
    risk_ok = actual_risk >= expected_risk_min
    
    # Overall success
    success = verdict_match and risk_ok
    
    # Scoring: 0 = complete bypass, 1 = partial (wrong verdict but some risk), 2 = full detection
    if success:
        score = 2
    elif actual_risk >= expected_risk_min * 0.5:  # At least half the expected risk
        score = 1
    else:
        score = 0  # Complete bypass
    
    return {
        "vector_id": vector.get("id"),
        "vector_name": vector.get("name"),
        "expected_verdict": expected_verdict,
        "actual_verdict": actual_verdict,
        "expected_risk_min": expected_risk_min,
        "actual_risk": actual_risk,
        "verdict_match": verdict_match,
        "risk_ok": risk_ok,
        "success": success,
        "score": score,
        "task_id": result.get("task_id"),
    }

async def run_evaluation():
    """Run full red team evaluation."""
    # Load attack vectors
    vectors_file = os.path.join(os.path.dirname(__file__), "attack_vectors.json")
    if not os.path.exists(vectors_file):
        print(f"ERROR: {vectors_file} not found")
        sys.exit(1)
    
    with open(vectors_file) as f:
        vectors = json.load(f)
    
    print(f"Loaded {len(vectors)} attack vectors")
    print("=" * 65)
    
    async with httpx.AsyncClient(timeout=30) as client:
        token = await get_token(client)
        print(f"Authenticated as {ADMIN_EMAIL}")
        
        results = []
        bypasses = []
        
        for i, vector in enumerate(vectors, 1):
            print(f"\n[{i}/{len(vectors)}] Testing: {vector.get('name', 'Unknown')}")
            
            try:
                # Submit
                submit_resp = await submit_investigation(client, token, vector)
                task_id = submit_resp.get("task_id")
                print(f"  Task ID: {task_id}")
                
                # Poll for result
                result = await poll_result(client, token, task_id)
                
                # Evaluate
                eval_result = evaluate_result(vector, result)
                results.append(eval_result)
                
                status_icon = "✅" if eval_result["success"] else "⚠️" if eval_result["score"] == 1 else "❌"
                print(f"  {status_icon} Verdict: {eval_result['actual_verdict']} (expected: {eval_result['expected_verdict']})")
                print(f"  Risk: {eval_result['actual_risk']} (min: {eval_result['expected_risk_min']})")
                
                # Record bypasses (score 0 or 1)
                if eval_result["score"] < 2:
                    bypass = {
                        "vector": vector,
                        "result": eval_result,
                        "timestamp": datetime.utcnow().isoformat(),
                        "status": "open"
                    }
                    bypasses.append(bypass)
                    
                    # Write to bypasses directory
                    bypass_file = os.path.join(os.path.dirname(__file__), "bypasses", f"{vector.get('id')}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json")
                    os.makedirs(os.path.dirname(bypass_file), exist_ok=True)
                    with open(bypass_file, "w") as f:
                        json.dump(bypass, f, indent=2)
                    print(f"  📝 Bypass recorded: {bypass_file}")
                    
            except Exception as e:
                print(f"  ERROR: {e}")
                results.append({
                    "vector_id": vector.get("id"),
                    "error": str(e),
                    "score": 0
                })
        
        # Summary
        print("\n" + "=" * 65)
        print("EVALUATION SUMMARY")
        print("=" * 65)
        
        total = len(results)
        full_detection = sum(1 for r in results if r.get("score") == 2)
        partial = sum(1 for r in results if r.get("score") == 1)
        bypasses_count = sum(1 for r in results if r.get("score") == 0)
        
        print(f"Total vectors tested: {total}")
        print(f"Full detection:       {full_detection} ({full_detection/total*100:.0f}%)")
        print(f"Partial detection:    {partial} ({partial/total*100:.0f}%)")
        print(f"Complete bypasses:    {bypasses_count} ({bypasses_count/total*100:.0f}%)")
        print(f"\nBypass files written: {len(bypasses)}")
        
        # Write summary
        summary = {
            "timestamp": datetime.utcnow().isoformat(),
            "total_vectors": total,
            "full_detection": full_detection,
            "partial": partial,
            "bypasses": bypasses_count,
            "results": results
        }
        with open(os.path.join(os.path.dirname(__file__), "last_evaluation.json"), "w") as f:
            json.dump(summary, f, indent=2)
        
        return bypasses_count

if __name__ == "__main__":
    bypasses = asyncio.run(run_evaluation())
    sys.exit(bypasses)  # Exit code = number of bypasses (0 = perfect score)
